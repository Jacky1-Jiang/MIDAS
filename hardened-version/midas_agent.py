"""MIDAS diagnostic agent: assembly of tools, middleware, and storage."""

import asyncio
import os
import re
import subprocess
import sys
import textwrap
from contextlib import AsyncExitStack
from typing import Any

from dotenv import load_dotenv
from langchain_openai import AzureChatOpenAI
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_core.tools import tool
from langchain.agents.middleware import (
    AgentMiddleware,
    ToolRetryMiddleware,
    ModelRetryMiddleware,
    ModelCallLimitMiddleware,
    ToolCallLimitMiddleware,
    ContextEditingMiddleware,
    ClearToolUsesEdit,
)

from deepagents import create_deep_agent
from deepagents.backends import CompositeBackend, StateBackend, StoreBackend
from langgraph.store.postgres.aio import AsyncPostgresStore

if __package__:
    from .midas_audit import PostgresAuditLog, ToolAuditMiddleware
    from .midas_authorization import (
        AuthorizationContext, AuthorizationPolicy,
        ToolAuthorizer, ToolAuthorizationMiddleware,
    )
    from .midas_ssh import create_ssh_diagnostic_tools
else:
    from midas_audit import PostgresAuditLog, ToolAuditMiddleware
    from midas_authorization import (
        AuthorizationContext, AuthorizationPolicy,
        ToolAuthorizer, ToolAuthorizationMiddleware,
    )
    from midas_ssh import create_ssh_diagnostic_tools

_agent_resources = AsyncExitStack()

# ============================================================================
# Local tools
# ============================================================================

PYTHON_EXEC = sys.executable
PROJECT_ROOT = os.getenv("MIDAS_PROJECT_ROOT", "/app")


@tool
def code_tool(code: str) -> str:
    """Execute Python code in a subprocess with a 30-second timeout.

    Args:
        code: Python source code to execute.

    Returns:
        Execution output or error message.
    """
    if not os.path.isfile(PYTHON_EXEC):
        return f"Error: Python executable not found at {PYTHON_EXEC}"
    try:
        result = subprocess.run(
            [PYTHON_EXEC, "-c", code],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            env={
                **os.environ,
                "PYTHONPATH": PROJECT_ROOT,
                "PYTHONUNBUFFERED": "1",
            },
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        if result.returncode != 0:
            return (
                f"Execution failed (exit code {result.returncode})\n"
                f"Stderr:\n{stderr}\nStdout:\n{stdout}"
            )
        output = stdout or "(no output)"
        return f"Execution succeeded.\nOutput:\n{textwrap.indent(output, '  ')}"
    except subprocess.TimeoutExpired:
        return "Error: Code execution timed out (30 seconds)."
    except Exception as e:
        return f"Error during execution: {e}"


# ============================================================================
# DiagnosticContextMiddleware
# ============================================================================

class DiagnosticContextMiddleware(AgentMiddleware):
    """Inject tool-selection hints based on keywords in the latest user message."""

    def __init__(self, store: AsyncPostgresStore):
        super().__init__()
        self.store = store

    def before_model(self, state, runtime) -> dict[str, Any] | None:
        messages = state.get("messages", [])
        if not messages:
            return None
        last_user_msg = None
        for m in reversed(messages):
            if hasattr(m, "type") and m.type == "human":
                last_user_msg = m.content
                break
        if not last_user_msg:
            return None
        msg_text = self._extract_text(last_user_msg)
        if not msg_text:
            return None

        hints = []
        if self._mentions_pv(msg_text):
            hints.append(
                "Hint: use EPICS tools to check PV status and PostgreSQL to query PV configuration"
            )
        if any(kw in msg_text.lower() for kw in ["log", "error", "exception"]):
            hints.append(
                "Hint: use Loki tools to query logs and read_service_logs for authorized service logs"
            )
        if any(kw in msg_text.lower() for kw in ["metric", "monitor", "prometheus", "target"]):
            hints.append("Hint: use Prometheus tools to query monitoring metrics")

        if hints:
            for hint in hints:
                print(f"  [DiagnosticContext] {hint}")
        return None

    @staticmethod
    def _extract_text(content) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block.get("text", ""))
                elif isinstance(block, str):
                    parts.append(block)
            return " ".join(parts)
        return str(content)

    @staticmethod
    def _mentions_pv(text: str) -> bool:
        pv_patterns = [r"\bpv\b", r"process\s+variable", r"EPICS"]
        return any(re.search(p, text, re.IGNORECASE) for p in pv_patterns)


# ============================================================================
# System prompt
# ============================================================================

SYSTEM_PROMPT = """You are the MIDAS diagnostic assistant for the DALS FEL control system.

## Available tools

### MCP remote services (auto-integrated)
- **epics**: Query EPICS PV values, connection state, and IOC status
- **loki**: Query the Loki log aggregation stack
- **prometheus**: Query Prometheus time-series monitoring data
- **postgres**: Query PostgreSQL configuration records

### Structured SSH diagnostics (allowlist-only)
- **get_service_status**: Read an authorized service's systemd state
- **read_service_logs**: Read bounded recent journal logs for an authorized service
- **list_listening_ports**: Read TCP/UDP listening sockets on an authorized host
- **list_processes**: Read process IDs and names on an authorized host

These four tools execute fixed command templates over SSH; only the host ID,
service ID, and line count are parameterized.  Raw shell commands, credentials,
and arbitrary arguments are never accepted.

### Local tools
- **code_tool**: Execute Python code in a sandboxed subprocess (30 s timeout)

### Built-in tools (provided by DeepAgent)
- **write_todos**: Manage a diagnostic task checklist
- **ls / read_file / write_file / edit_file**: File-system operations
  - Files under `/memories/` are persisted to PostgreSQL
  - All other paths are transient

## Workflow
1. Understand the reported symptom and identify the diagnostic goal
2. For complex problems, create a task plan with write_todos
3. Query data sources: metrics -> logs -> SSH host inspection as needed
4. Record important findings under /memories/ for future reference
5. Present a clear root-cause conclusion with supporting evidence and
   remediation recommendations for operator review

## Principles
- Think before calling tools; select the most relevant data source first
- Least privilege: prefer read-only queries over write operations
- On tool failure, analyze the cause and try alternative data sources
- Summarize key findings; avoid pasting large raw outputs
- All remediation actions are recommendations for operator approval
"""


# ============================================================================
# Initialization
# ============================================================================

async def setup_components():
    """Initialize the PostgreSQL-backed persistent store."""
    database_url = os.environ["MIDAS_MEMORY_DATABASE_URL"]
    store = await _agent_resources.enter_async_context(
        AsyncPostgresStore.from_conn_string(database_url)
    )
    if os.getenv("MIDAS_SETUP_MEMORY_STORE", "0") == "1":
        await store.setup()
    return store


async def close_agent_resources():
    """Release memory-store resources during application shutdown."""
    await _agent_resources.aclose()


def make_backend(runtime):
    """Create a composite backend: transient state + persistent /memories/."""
    return CompositeBackend(
        default=StateBackend(runtime),
        routes={"/memories/": StoreBackend(runtime)},
    )


async def create_agent_graph():
    """Assemble and return the configured MIDAS diagnostic agent."""
    load_dotenv(".env")

    # -- Authorization policy ------------------------------------------------
    policy = AuthorizationPolicy.load(os.getenv("MIDAS_AUTHORIZATION_POLICY", ""))
    authorizer = ToolAuthorizer(policy)

    # -- Audit log -----------------------------------------------------------
    audit_log = PostgresAuditLog(os.getenv("MIDAS_AUDIT_DATABASE_URL", ""))
    await audit_log.acheck()

    # -- LLM -----------------------------------------------------------------
    model = AzureChatOpenAI(
        azure_deployment=os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-5.2"),
        api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-12-01-preview"),
        temperature=1,
        max_tokens=None,
        timeout=None,
        max_retries=2,
    )

    # -- MCP tool integration ------------------------------------------------
    mcp_config = {
        "epics":      {"url": os.environ["MIDAS_MCP_EPICS_URL"],      "transport": "sse"},
        "loki":       {"url": os.environ["MIDAS_MCP_LOKI_URL"],       "transport": "sse"},
        "prometheus": {"url": os.environ["MIDAS_MCP_PROMETHEUS_URL"], "transport": "sse"},
        "postgres":   {"url": os.environ["MIDAS_MCP_POSTGRES_URL"],   "transport": "sse"},
    }
    client = MultiServerMCPClient(mcp_config)
    mcp_tools = await client.get_tools()
    ssh_tools = create_ssh_diagnostic_tools(authorizer)
    all_tools = mcp_tools + ssh_tools + [code_tool]

    tool_names = [t.name for t in all_tools]
    if len(tool_names) != len(set(tool_names)):
        raise ValueError("Duplicate tool names would make authorization ambiguous")

    # -- Persistent store ----------------------------------------------------
    store = await setup_components()

    # -- Middleware stack (execution order) -----------------------------------
    middleware = [
        # Audit: record every tool call before and after execution
        ToolAuditMiddleware(audit_log, context_provider=authorizer.audit_context),

        # Authorization: default-deny check against the loaded policy
        ToolAuthorizationMiddleware(authorizer),

        # Call limits
        ModelCallLimitMiddleware(
            run_limit=20,
            thread_limit=100,
            exit_behavior="end",
        ),
        *[
            ToolCallLimitMiddleware(
                tool_name=t.name, run_limit=3, exit_behavior="continue",
            )
            for t in ssh_tools
        ],
        ToolCallLimitMiddleware(
            run_limit=30,
            thread_limit=200,
            exit_behavior="continue",
        ),

        # Retry: MCP services only
        ToolRetryMiddleware(
            max_retries=3,
            tools=["epics", "loki", "prometheus", "postgres"],
            retry_on=(ConnectionError, TimeoutError, Exception),
            backoff_factor=2.0,
            initial_delay=1.0,
            on_failure="return_message",
        ),
        ModelRetryMiddleware(
            max_retries=2,
            on_failure="continue",
            backoff_factor=2.0,
        ),

        # Context management
        ContextEditingMiddleware(
            edits=[
                ClearToolUsesEdit(
                    trigger=80000,
                    keep=5,
                    clear_tool_inputs=False,
                    exclude_tools=["postgres"],
                ),
            ],
        ),

        # Diagnostic context hints
        DiagnosticContextMiddleware(store),
    ]

    # -- Assemble agent ------------------------------------------------------
    agent = create_deep_agent(
        system_prompt=SYSTEM_PROMPT,
        model=model,
        tools=all_tools,
        store=store,
        backend=make_backend,
        middleware=middleware,
        context_schema=AuthorizationContext,
    )

    print("=" * 60)
    print("MIDAS diagnostic agent initialized")
    print("=" * 60)
    print(f"\nMiddleware ({len(middleware)}):")
    for i, mw in enumerate(middleware, 1):
        print(f"  {i:2d}. {mw.name}")
    print(f"\nTools ({len(all_tools)}):")
    for i, t in enumerate(all_tools, 1):
        print(f"  {i:2d}. {t.name}")
    print(f"\nStorage: StateBackend (transient) + PostgreSQL (/memories/)")
    print(f"Audit:   midas_audit.tool_events (PostgreSQL)")
    print("=" * 60)

    return agent


# ============================================================================
# Entry point
# ============================================================================

try:
    loop = asyncio.get_event_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

try:
    graph = loop.run_until_complete(create_agent_graph())
except BaseException:
    loop.run_until_complete(close_agent_resources())
    raise

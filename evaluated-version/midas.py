"""
重构后的自由电子激光装置控制系统运维Agent
使用 DeepAgent + Middleware 架构
"""
import asyncio
import dataclasses
import json
import math
import os
import re
import subprocess
import sys
import textwrap
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import NAMESPACE_URL, uuid4, uuid5

from dotenv import load_dotenv
import paramiko
import psycopg
from psycopg.types.json import Jsonb

from langchain_openai import AzureChatOpenAI
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_core.tools import tool
from langchain.agents.middleware import (
    AgentMiddleware,
    AgentState,
    ToolRetryMiddleware,
    ModelRetryMiddleware,
    ModelCallLimitMiddleware,
    ToolCallLimitMiddleware,
    ContextEditingMiddleware,
    ClearToolUsesEdit,
    hook_config,
)
from langchain.tools.tool_node import ToolCallRequest
from langchain.messages import ToolMessage
from langgraph.config import get_config
from langgraph.types import Command
from typing_extensions import NotRequired

from deepagents import create_deep_agent
from deepagents.backends import CompositeBackend, StateBackend, StoreBackend
from langgraph.store.postgres.aio import AsyncPostgresStore

# ============================================================================
# 工具定义
# ============================================================================

PYTHON_EXEC = sys.executable
PROJECT_ROOT = "/app"


@tool
def code_tool(code: str) -> str:
    """Execute Python code using the current interpreter (works in container and host).
    
    Uses: <current_python> -c "your_code"
    Working directory: /app
    
    Args:
        code: Python code to execute
        
    Returns:
        Execution result or error message
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
            }
        )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode != 0:
            return f"Execution failed (exit code {result.returncode})\nStderr:\n{stderr}\nStdout:\n{stdout}"
        else:
            output = stdout or "(no output)"
            return f"Execution succeeded.\nOutput:\n{textwrap.indent(output, '  ')}"

    except subprocess.TimeoutExpired:
        return "Error: Code execution timed out (30 seconds)."
    except Exception as e:
        return f"Error during execution: {str(e)}"


@tool
def ssh_tool(
    ip_address: str, 
    password: str, 
    username: str = "root", 
    command: str = "echo 'Connected successfully'"
) -> str:
    """Connect to a remote server via SSH using the provided IP address and password.
    
    ⚠️ 安全提示: 此工具受SSHSafetyMiddleware保护，危险命令将被自动拦截。
    
    Args:
        ip_address: The IP address of the remote server
        password: The password for authentication (default from context: dcls2501)
        username: The username for login (default: root)
        command: The command to execute on the remote server
        
    Returns:
        The result of SSH connection and command execution
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        ssh.connect(ip_address, username=username, password=password, timeout=10)
        
        stdin, stdout, stderr = ssh.exec_command(command)
        
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        
        ssh.close()
        
        if error:
            return f"SSH connection succeeded but command execution had errors:\n{error}"
        else:
            output_text = output or "(no output)"
            return f"SSH connection and command execution succeeded.\nOutput:\n{textwrap.indent(output_text, '  ')}"

    except paramiko.AuthenticationException:
        return "SSH Authentication failed. Please check your username and password."
    except paramiko.SSHException as e:
        return f"SSH connection failed: {str(e)}"
    except Exception as e:
        return f"Error during SSH connection: {str(e)}"


# ============================================================================
# 自定义Middleware
# ============================================================================

class SSHSafetyMiddleware(AgentMiddleware):
    """SSH安全中间件：拦截危险的SSH命令"""
    
    DANGEROUS_PATTERNS = [
    # ===== 原有规则 =====
    r'\brm\s+',
    r'\breboot\b',
    r'\bshutdown\b',
    r'\bpoweroff\b',
    r'\bhalt\b',
    r'\bkill\s+',
    r'\bdd\s+if=',
    r'\bmkfs\b',
    r'\bformat\b',
    r'\binit\s+0\b',
    r'\binit\s+6\b',

    # ===== Docker 危险操作 =====
    r'\bdocker\s+rm\b',
    r'\bdocker\s+rmi\b',
    r'\bdocker\s+stop\b',
    r'\bdocker\s+kill\b',
    r'\bdocker\s+prune\b',
    r'\bdocker\s+restart\b',
    r'\bdocker\s+exec\b',
    r'\bdocker-compose\s+down\b',
    r'\bdocker-compose\s+stop\b',

    # ===== 文件写操作 =====
    r'\bvi\b',
    r'\bvim\b',
    r'\bnano\b',
    r'\bsed\s+.*-i\b',
    r'\bchmod\b',
    r'\bchown\b',

    # ===== 软件安装/卸载 =====
    r'\bapt\s+(install|remove)\b',
    r'\byum\s+(install|remove)\b',
    r'\bpip\s+(install|uninstall)\b',

    # ===== 服务管理（除status外）=====
    r'\bsystemctl\s+(start|stop|restart|disable|mask|enable)\b',

    # ===== 系统配置修改 =====
    r'\bcrontab\b',
    r'\biptables\b',
    r'\bip\s+addr\s+(add|del)\b',
    r'\bpasswd\b',
    r'\buseradd\b',
    r'\buserdel\b',
    ]
    
    def _check_dangerous_command(self, request: ToolCallRequest) -> ToolMessage | None:
        """检查是否为危险命令，返回错误消息或None"""
        if request.tool_call['name'] != 'ssh_tool':
            return None
            
        command = request.tool_call['args'].get('command', '')
        ip = request.tool_call['args'].get('ip_address', 'unknown')
        
        # 检查危险命令
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                print(f"🚨 [安全拦截] SSH到 {ip} 的危险命令被阻止: {command}")
                return ToolMessage(
                    content=f"❌ 安全策略拒绝: 检测到危险命令 '{command}'\n"
                            f"该命令可能导致系统损坏或服务中断。\n"
                            f"如确需执行，请联系系统管理员手动操作。",
                    tool_call_id=request.tool_call['id'],
                    status="error",
                    artifact={
                        "midas_audit_outcome": "rejected",
                        "reason": "ssh_command_blocked",
                        "matched_pattern": pattern,
                    },
                )
        
        # 记录SSH操作
        print(f"⚠️  [SSH操作] 目标: {ip}, 命令: {command}")
        return None
    
    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command],
    ) -> ToolMessage | Command:
        """同步版本：拦截SSH工具调用"""
        error_msg = self._check_dangerous_command(request)
        if error_msg:
            return error_msg
        return handler(request)
    
    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Any],
    ) -> ToolMessage | Command:
        """异步版本：拦截SSH工具调用"""
        error_msg = self._check_dangerous_command(request)
        if error_msg:
            return error_msg
        return await handler(request)


class AuditPersistenceError(RuntimeError):
    """审计记录无法持久化时阻止后续工具调用。"""


class AuditState(AgentState):
    midas_audit_run_id: NotRequired[str]


SENSITIVE_AUDIT_KEYS = {
    "password", "passwd", "pwd", "secret", "clientsecret", "token",
    "accesstoken", "refreshtoken", "apikey", "authorization", "privatekey",
    "cookie", "setcookie", "credential", "credentials",
}


def _audit_normalize(value: Any) -> Any:
    """将工具参数和返回值转换为可写入 JSONB 的对象。"""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, dict):
        return {str(key): _audit_normalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_audit_normalize(item) for item in value]
    if hasattr(value, "model_dump"):
        return _audit_normalize(value.model_dump(mode="python"))
    if dataclasses.is_dataclass(value):
        return _audit_normalize(dataclasses.asdict(value))
    return str(value)


def _is_sensitive_audit_key(key: str) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", key.lower())
    return compact in SENSITIVE_AUDIT_KEYS or compact.endswith(
        ("password", "apikey", "token", "secret")
    )


def _audit_secret_values(value: Any) -> set[str]:
    """收集敏感字段的原始值，以便同时从工具返回内容中脱敏。"""
    secrets: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if _is_sensitive_audit_key(str(key)) and isinstance(item, str) and item:
                secrets.add(item)
            secrets.update(_audit_secret_values(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            secrets.update(_audit_secret_values(item))
    return secrets


def _audit_redact(value: Any, secrets: set[str] | None = None) -> Any:
    """递归脱敏密码、令牌、API Key和带凭据的连接字符串。"""
    value = _audit_normalize(value)
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _is_sensitive_audit_key(key)
            else _audit_redact(item, secrets)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_audit_redact(item, secrets) for item in value]
    if isinstance(value, str):
        for secret in sorted(secrets or (), key=len, reverse=True):
            value = value.replace(secret, "[REDACTED]")
        value = re.sub(
            r"(?i)(\b(?:postgres(?:ql)?|https?)://)[^\s/@]+:[^\s/@]+@",
            r"\1[REDACTED]@",
            value,
        )
        value = re.sub(
            r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/-]+=*",
            r"\1[REDACTED]",
            value,
        )
        return value.replace("\x00", "\\u0000")
    return value


class PostgresAuditLog:
    """在独立的 PostgreSQL 表中持久化工具调用生命周期事件。"""

    CREATE_STATEMENTS = (
        "CREATE SCHEMA IF NOT EXISTS midas_audit",
        """
        CREATE TABLE IF NOT EXISTS midas_audit.tool_events (
            event_id              UUID        PRIMARY KEY,
            audit_call_id         UUID        NOT NULL,
            run_id                TEXT,
            thread_id             TEXT,
            tool_call_id          TEXT,
            tool_name             TEXT        NOT NULL,
            phase                 TEXT        NOT NULL,
            occurred_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
            duration_ms           DOUBLE PRECISION,
            arguments             JSONB,
            result                JSONB,
            error                 JSONB
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_midas_tool_events_run
        ON midas_audit.tool_events (run_id, occurred_at)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_midas_tool_events_thread
        ON midas_audit.tool_events (thread_id, occurred_at)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_midas_tool_events_tool
        ON midas_audit.tool_events (tool_name, occurred_at)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_midas_tool_events_phase
        ON midas_audit.tool_events (phase, occurred_at)
        """,
    )

    INSERT = """
        INSERT INTO midas_audit.tool_events
            (event_id, audit_call_id, run_id, thread_id, tool_call_id,
             tool_name, phase, occurred_at, duration_ms,
             arguments, result, error)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    def __init__(self, database_url: str, timeout_s: int = 5):
        if not database_url:
            raise ValueError("MIDAS_AUDIT_DATABASE_URL must be configured")
        self.database_url = database_url
        self.timeout_s = timeout_s
        self.connection_options = {
            "connect_timeout": timeout_s,
            "autocommit": True,
            "options": (
                f"-c statement_timeout={timeout_s * 1000} "
                f"-c lock_timeout={timeout_s * 1000}"
            ),
            "application_name": "midas-audit",
        }

    @staticmethod
    def _parameters(event: dict) -> tuple:
        return (
            event["event_id"], event["audit_call_id"], event.get("run_id"),
            event.get("thread_id"), event.get("tool_call_id"), event["tool_name"],
            event["phase"], event["occurred_at"], event.get("duration_ms"),
            Jsonb(event["arguments"]),
            Jsonb(event["result"]) if event.get("result") is not None else None,
            Jsonb(event["error"]) if event.get("error") is not None else None,
        )

    async def asetup(self):
        """启动时创建审计表并验证当前数据库用户具有 INSERT 权限。"""
        async with await psycopg.AsyncConnection.connect(
            self.database_url, **self.connection_options
        ) as connection:
            for statement in self.CREATE_STATEMENTS:
                await connection.execute(statement)
            cursor = await connection.execute(
                "SELECT has_table_privilege(current_user, "
                "'midas_audit.tool_events', 'INSERT')"
            )
            if not (await cursor.fetchone())[0]:
                raise AuditPersistenceError("The audit database user lacks INSERT permission")

    def append(self, event: dict):
        with psycopg.connect(self.database_url, **self.connection_options) as connection:
            connection.execute(self.INSERT, self._parameters(event))

    async def aappend(self, event: dict):
        async def insert():
            async with await psycopg.AsyncConnection.connect(
                self.database_url, **self.connection_options
            ) as connection:
                await connection.execute(self.INSERT, self._parameters(event))

        await asyncio.wait_for(insert(), timeout=self.timeout_s * 2)


class ToolAuditMiddleware(AgentMiddleware):
    """将所有工具调用的请求、结果、拦截和异常写入 PostgreSQL。"""

    state_schema = AuditState

    def __init__(self, audit_log: PostgresAuditLog):
        super().__init__()
        self.audit_log = audit_log
        self._failed = threading.Event()

    def _ensure_available(self):
        if self._failed.is_set():
            raise AuditPersistenceError(
                "Audit storage failed; restart the agent after database recovery"
            )

    def _append(self, event: dict):
        self._ensure_available()
        try:
            self.audit_log.append(event)
        except Exception:
            self._failed.set()
            raise AuditPersistenceError(
                "Audit persistence failed; further tool calls are disabled"
            ) from None

    async def _aappend(self, event: dict):
        self._ensure_available()
        try:
            await self.audit_log.aappend(event)
        except asyncio.CancelledError:
            self._failed.set()
            raise
        except Exception:
            self._failed.set()
            raise AuditPersistenceError(
                "Audit persistence failed; further tool calls are disabled"
            ) from None

    def before_agent(self, state, runtime):
        self._ensure_available()
        return {"midas_audit_run_id": str(uuid4())}

    async def abefore_agent(self, state, runtime):
        return self.before_agent(state, runtime)

    @staticmethod
    def _context(state, runtime) -> dict:
        config = getattr(runtime, "config", None)
        if config is None:
            try:
                config = get_config()
            except RuntimeError:
                config = {}
        metadata = config.get("metadata") or {}
        configurable = config.get("configurable") or {}
        return {
            "run_id": str(
                metadata.get("run_id")
                or configurable.get("run_id")
                or state.get("midas_audit_run_id")
                or ""
            ) or None,
            "thread_id": str(
                configurable.get("thread_id") or metadata.get("thread_id") or ""
            ) or None,
        }

    def _call(self, tool_call: dict, state, runtime) -> tuple[dict, set[str]]:
        context = self._context(state, runtime)
        tool_call_id = str(tool_call.get("id") or "") or None
        correlation_key = ":".join(filter(None, (
            context["run_id"], context["thread_id"], tool_call_id,
        )))
        audit_call_id = (
            str(uuid5(NAMESPACE_URL, correlation_key)) if correlation_key else str(uuid4())
        )
        arguments = _audit_normalize(tool_call.get("args", {}))
        secrets = _audit_secret_values(arguments)
        return {
            **context,
            "audit_call_id": audit_call_id,
            "tool_call_id": tool_call_id,
            "tool_name": tool_call["name"],
            "arguments": _audit_redact(arguments, secrets),
        }, secrets

    @staticmethod
    def _event(call: dict, phase: str, **fields) -> dict:
        return {
            **call,
            "event_id": str(uuid4()),
            "phase": phase,
            "occurred_at": datetime.now(timezone.utc),
            **fields,
        }

    def after_model(self, state, runtime) -> dict[str, Any] | None:
        """先记录模型提出的调用，确保被限流或安全拦截的请求仍有记录。"""
        last_message = state["messages"][-1] if state.get("messages") else None
        for tool_call in getattr(last_message, "tool_calls", []) if last_message else []:
            call, _ = self._call(tool_call, state, runtime)
            self._append(self._event(call, "proposed"))
        return None

    async def aafter_model(self, state, runtime) -> dict[str, Any] | None:
        last_message = state["messages"][-1] if state.get("messages") else None
        for tool_call in getattr(last_message, "tool_calls", []) if last_message else []:
            call, _ = self._call(tool_call, state, runtime)
            await self._aappend(self._event(call, "proposed"))
        return None

    @staticmethod
    def _outcome(result: Any) -> str:
        artifact = getattr(result, "artifact", None)
        if isinstance(artifact, dict) and artifact.get("midas_audit_outcome") == "rejected":
            return "rejected"
        content = getattr(result, "content", result)
        if isinstance(content, str) and content.startswith("❌ 安全策略拒绝"):
            return "rejected"
        if getattr(result, "status", None) == "error":
            return "tool_error"
        if isinstance(content, str):
            try:
                payload = json.loads(content)
            except (ValueError, TypeError):
                payload = None
            if isinstance(payload, dict) and (
                payload.get("status") == "error" or payload.get("isError") is True
            ):
                return "tool_error"
            if content.startswith(("Error:", "Error during ", "Execution failed")):
                return "tool_error"
        return "returned"

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command],
    ) -> ToolMessage | Command:
        call, secrets = self._call(
            request.tool_call, request.runtime.state, request.runtime
        )
        self._append(self._event(call, "started"))
        started = time.perf_counter()
        try:
            result = handler(request)
        except BaseException as error:
            phase = (
                "cancelled"
                if isinstance(error, (asyncio.CancelledError, KeyboardInterrupt, SystemExit))
                else "exception"
            )
            self._append(self._event(
                call,
                phase,
                duration_ms=(time.perf_counter() - started) * 1000,
                error=_audit_redact(
                    {"type": type(error).__name__, "message": str(error)}, secrets
                ),
            ))
            raise
        self._append(self._event(
            call,
            self._outcome(result),
            duration_ms=(time.perf_counter() - started) * 1000,
            result=_audit_redact(result, secrets),
        ))
        return result

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Any],
    ) -> ToolMessage | Command:
        call, secrets = self._call(
            request.tool_call, request.runtime.state, request.runtime
        )
        await self._aappend(self._event(call, "started"))
        started = time.perf_counter()
        try:
            result = await handler(request)
        except BaseException as error:
            phase = (
                "cancelled"
                if isinstance(error, (asyncio.CancelledError, KeyboardInterrupt, SystemExit))
                else "exception"
            )
            await self._aappend(self._event(
                call,
                phase,
                duration_ms=(time.perf_counter() - started) * 1000,
                error=_audit_redact(
                    {"type": type(error).__name__, "message": str(error)}, secrets
                ),
            ))
            raise
        await self._aappend(self._event(
            call,
            self._outcome(result),
            duration_ms=(time.perf_counter() - started) * 1000,
            result=_audit_redact(result, secrets),
        ))
        return result


class DiagnosticContextMiddleware(AgentMiddleware):
    """诊断上下文中间件：动态注入相关的历史故障信息"""
    
    def __init__(self, store: AsyncPostgresStore):
        super().__init__()
        self.store = store
    
    def before_model(self, state, runtime) -> dict[str, Any] | None:
        """在模型调用前，根据问题类型动态加载上下文"""
        messages = state.get('messages', [])
        if not messages:
            return None
        
        # 获取最后一条用户消息
        last_user_msg = None
        for m in reversed(messages):
            if hasattr(m, 'type') and m.type == 'human':
                last_user_msg = m.content
                break
        
        if not last_user_msg:
            return None
        
        # 将消息内容转换为字符串（处理可能的list/str类型）
        msg_text = self._extract_text_content(last_user_msg)
        if not msg_text:
            return None
        
        # 分析问题类型
        context_hints = []
        
        # 检测是否提到PV
        if self._mentions_pv(msg_text):
            context_hints.append("💡 提示: 可以使用 epics 工具检查PV状态，使用 postgres 查询PV配置信息")
        
        # 检测是否提到日志
        if any(keyword in msg_text.lower() for keyword in ['日志', 'log', '错误', 'error']):
            context_hints.append("💡 提示: 可以使用 loki 工具查询日志，使用 ssh_tool 查看服务器本地日志")
        
        # 检测是否提到指标
        if any(keyword in msg_text.lower() for keyword in ['监控', '指标', 'metric', '性能']):
            context_hints.append("💡 提示: 可以使用 prometheus 工具查询监控指标")
        
        if context_hints:
            print(f"🧠 [上下文增强] 检测到相关提示")
            for hint in context_hints:
                print(f"   {hint}")
        
        return None
    
    def _extract_text_content(self, content) -> str:
        """提取消息内容的文本（处理str或list类型）"""
        if isinstance(content, str):
            return content
        elif isinstance(content, list):
            # 如果是列表，提取所有text类型的块
            text_parts = []
            for block in content:
                if isinstance(block, dict) and block.get('type') == 'text':
                    text_parts.append(block.get('text', ''))
                elif isinstance(block, str):
                    text_parts.append(block)
            return ' '.join(text_parts)
        else:
            return str(content)
    
    def _mentions_pv(self, text: str) -> bool:
        """检测是否提到PV相关内容"""
        if not isinstance(text, str):
            return False
        
        pv_patterns = [
            r'\bpv\b',
            r'process\s+variable',
            r'EPICS',
        ]
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in pv_patterns)


# ============================================================================
# System Prompt（简化版）
# ============================================================================

SYSTEM_PROMPT = """你是自由电子激光装置控制系统运维助手，具备强大的工具调用能力和上下文感知能力。

## 🧰 可用工具

### MCP远程服务（自动集成）
- **epics**: 查询EPICS控制系统中PV变量的信息
- **loki**: 查询日志系统
- **prometheus**: 查询监控指标
- **postgres**: 查询数据库中PV的详细配置信息

### 本地工具
- **code_tool**: 在本地容器中安全执行Python代码（工作目录：/app）
  - 适用于：数据处理、脚本生成、配置解析、临时计算
  - 超时限制：30秒

- **ssh_tool**: 通过SSH登录远程服务器执行命令
  - 默认配置：username="root", password="dcls2501"
  - ⚠️ 受安全策略保护：危险命令会被自动拦截
  - 优先使用只读命令（cat, ps, systemctl status等）

### 内置工具（由DeepAgent提供）
- **write_todos**: 管理任务清单（用于复杂多步骤诊断）
- **ls/read_file/write_file/edit_file**: 文件系统操作
  - `/memories/` 路径下的文件会持久化保存
  - 其他路径为临时存储

## 🎯 工作流程

1. **理解问题** - 明确故障现象和诊断目标
2. **制定计划** - 对于复杂问题，使用 write_todos 记录诊断步骤
3. **组合工具** - 先查指标 → 再查日志 → 必要时SSH验证
4. **记录发现** - 将重要信息写入 /memories/ 以便后续参考
5. **给出结论** - 清晰说明根因、支持证据和建议措施

## 💡 最佳实践

- **先思考，再调用**: 明确问题本质后再选择工具
- **最小权限原则**: 能用只读命令就不用写命令
- **失败处理**: 工具调用失败时分析原因并尝试其他方法
- **输出清晰**: 总结关键信息，避免直接粘贴大段原始输出
- **结构化诊断**: 最终诊断前整理 root_cause、affected_ioc、observed_symptoms、alternative_causes

## 📊 示例场景

**用户**: "xxx PV为什么下线了？"
**诊断流程**:
1. 使用 epics/caget 检查PV是否能连接
2. 如无响应，使用 postgres 查询该PV所在IOC的IP地址
3. 使用 ssh_tool 登录控制节点检查服务状态和网络连接

记住：你是专家级运维助手，目标是快速准确地解决问题！"""


# ============================================================================
# 配置和初始化
# ============================================================================

async def setup_components():
    """初始化PostgreSQL存储"""
    DB_URI = "postgresql://dcls:dcls2501@localhost:5432/deepAgent?sslmode=disable"
    store = AsyncPostgresStore.from_conn_string(DB_URI)
    return store


def make_backend(runtime):
    """创建复合后端：临时存储 + 持久化存储"""
    return CompositeBackend(
        default=StateBackend(runtime),  # 临时存储
        routes={
            "/memories/": StoreBackend(runtime),  # PostgreSQL持久化
        }
    )


async def create_agent_graph():
    """创建并配置运维Agent"""
    
    # 1. 加载环境变量
    load_dotenv(".env")
    azure_openai_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
    azure_openai_api_key = os.getenv("AZURE_OPENAI_API_KEY")

    # 审计使用独立的 PostgreSQL 连接。启动时创建表并检查 INSERT 权限；
    # 初始化失败则拒绝启动，避免工具调用脱离审计边界。
    audit_log = PostgresAuditLog(os.getenv("MIDAS_AUDIT_DATABASE_URL", ""))
    await audit_log.asetup()
    
    # 2. 初始化模型
    model = AzureChatOpenAI(
        azure_deployment="gpt-5.2",
        api_version="2024-12-01-preview",
        temperature=1,
        max_tokens=None,
        timeout=None,
        max_retries=2,
    )
    
    # 3. 初始化MCP客户端
    client = MultiServerMCPClient({
        "epics": {
            "url": "http://192.168.20.170:8003/sse",
            "transport": "sse"
        },
        "loki": {
            "url": "http://192.168.20.251:8001/sse",
            "transport": "sse"
        },
        "prometheus": {
            "url": "http://192.168.20.170:8001/sse",
            "transport": "sse"
        },
        "postgres": {
            "url": "http://192.168.20.251:8002/sse",
            "transport": "sse"
        },
    })
    
    # 4. 获取工具
    mcp_tools = await client.get_tools()
    all_tools = mcp_tools + [code_tool, ssh_tool]
    
    # 5. 初始化存储
    store = await setup_components()
    
    # 6. 配置Middleware（按执行顺序）
    middleware = [
        # 审计必须位于工具包装链最外层，才能记录成功、失败及安全拦截结果。
        ToolAuditMiddleware(audit_log),

        # ==================== 限制类（最先执行）====================
        ModelCallLimitMiddleware(
            run_limit=20,        # 单次诊断最多20轮模型调用
            thread_limit=100,    # 整个会话最多100次
            exit_behavior="end",
        ),
        
        ToolCallLimitMiddleware(
            tool_name="ssh_tool",
            run_limit=3,         # 单次诊断最多3次SSH调用（防止滥用）
            exit_behavior="continue",
        ),
        
        ToolCallLimitMiddleware(
            run_limit=30,        # 所有工具总共30次
            thread_limit=200,
            exit_behavior="continue",
        ),
        
        # ==================== 重试类（提升可靠性）====================
        ToolRetryMiddleware(
            max_retries=3,
            tools=["epics", "loki", "prometheus", "postgres"],  # 只对MCP服务重试
            retry_on=(ConnectionError, TimeoutError, Exception),
            backoff_factor=2.0,
            initial_delay=1.0,
            on_failure="return_message",  # 失败时返回错误信息而非抛异常
        ),
        
        ModelRetryMiddleware(
            max_retries=2,
            on_failure="continue",  # 模型失败时返回错误信息，允许Agent处理
            backoff_factor=2.0,
        ),
        
        # ==================== 上下文管理（优化长对话）====================
        ContextEditingMiddleware(
            edits=[
                ClearToolUsesEdit(
                    trigger=80000,      # 8万token时触发清理
                    keep=5,             # 保留最近5次工具调用结果
                    clear_tool_inputs=False,  # 保留工具调用参数以便追溯
                    exclude_tools=["postgres"],  # postgres结果可能重要，不清理
                    placeholder="[内容已清理以节省上下文空间]",
                ),
            ],
        ),
        
        # ==================== 自定义中间件（业务逻辑）====================
        SSHSafetyMiddleware(),              # SSH安全拦截
        DiagnosticContextMiddleware(store), # 诊断上下文增强
    ]
    
    # 7. 创建Deep Agent
    agent = create_deep_agent(
        system_prompt=SYSTEM_PROMPT,
        model=model,
        tools=all_tools,
        store=store,
        backend=make_backend,
        middleware=middleware,
    )
    
    print("=" * 60)
    print("🚀 运维Agent初始化成功！")
    print("=" * 60)
    print("\n已加载的Middleware:")
    print("  1. ToolAuditMiddleware - PostgreSQL工具审计")
    print("  2. ModelCallLimitMiddleware - 模型调用限制")
    print("  3. ToolCallLimitMiddleware (ssh_tool) - SSH调用限制")
    print("  4. ToolCallLimitMiddleware (global) - 全局工具限制")
    print("  5. ToolRetryMiddleware - MCP服务重试")
    print("  6. ModelRetryMiddleware - 模型调用重试")
    print("  7. ContextEditingMiddleware - 上下文清理")
    print("  8. SSHSafetyMiddleware - SSH安全拦截")
    print("  9. DiagnosticContextMiddleware - 诊断上下文增强")
    print(" 10. TodoListMiddleware - 任务规划（DeepAgent内置）")
    print(" 11. FilesystemMiddleware - 文件系统（DeepAgent内置）")
    print(" 12. SubAgentMiddleware - 子Agent（DeepAgent内置）")
    
    print("\n可用工具:")
    for i, tool in enumerate(all_tools, 1):
        print(f" {i:2d}. {tool.name}")
    
    print("\n存储配置:")
    print("  - 临时存储: StateBackend")
    print("  - 持久化存储: PostgreSQL (/memories/ 路径)")
    print("  - 工具审计: PostgreSQL (midas_audit.tool_events)")
    print("=" * 60)
    
    return agent
# ============================================================================
# 启动入口
# ============================================================================

# 创建或获取事件循环
try:
    loop = asyncio.get_event_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

# 初始化全局Agent
graph = loop.run_until_complete(create_agent_graph())

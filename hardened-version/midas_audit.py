"""Durable tool-call auditing with PostgreSQL persistence.

Every tool invocation — whether executed, rejected, or failed — is recorded
in an append-only ``midas_audit.tool_events`` table.  If the audit write
itself fails, further tool calls are blocked until the agent is restarted,
ensuring that no diagnostic action escapes the audit trail.
"""

import asyncio
import dataclasses
import json
import math
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import psycopg
from psycopg.types.json import Jsonb
from langchain.agents.middleware import AgentMiddleware, AgentState
from langgraph.config import get_config
from typing_extensions import NotRequired


class AuditPersistenceError(RuntimeError):
    """The audit boundary failed; tool execution must stop."""


class AuditState(AgentState):
    midas_audit_run_id: NotRequired[str]


# ---------------------------------------------------------------------------
# Credential redaction
# ---------------------------------------------------------------------------

SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "secret", "clientsecret", "token",
    "accesstoken", "refreshtoken", "apikey", "authorization", "privatekey",
    "cookie", "setcookie", "credential", "credentials",
}

SECRET_ASSIGNMENT = re.compile(
    r"(?i)((?:[\"']?)(?:password|passwd|pwd|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|token|secret)(?:[\"']?)\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;}]+)"
)


def normalize(value: Any) -> Any:
    """Recursively convert arbitrary Python objects to JSON-safe primitives."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, dict):
        return {str(key): normalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [normalize(item) for item in value]
    if hasattr(value, "model_dump"):
        return normalize(value.model_dump(mode="python"))
    if dataclasses.is_dataclass(value):
        return normalize(dataclasses.asdict(value))
    return str(value)


def sensitive_key(key: str) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", key.lower())
    return compact in SENSITIVE_KEYS or compact.endswith(
        ("password", "apikey", "token", "secret")
    )


def secret_values(value: Any) -> set[str]:
    """Collect string values associated with sensitive keys for redaction."""
    secrets = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if sensitive_key(str(key)) and isinstance(item, str) and item:
                secrets.add(item)
            secrets.update(secret_values(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            secrets.update(secret_values(item))
    return secrets


def redact(value: Any, secrets: set[str] | None = None) -> Any:
    """Deep-redact sensitive keys, known secret values, and credential patterns."""
    value = normalize(value)
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if sensitive_key(key) else redact(item, secrets)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item, secrets) for item in value]
    if isinstance(value, str):
        for secret in sorted(secrets or (), key=len, reverse=True):
            value = value.replace(secret, "[REDACTED]")
        value = SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", value)
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


# ---------------------------------------------------------------------------
# PostgreSQL audit log
# ---------------------------------------------------------------------------

class PostgresAuditLog:
    """Append-only audit event writer backed by PostgreSQL."""

    INSERT = """
        INSERT INTO midas_audit.tool_events
            (event_id, audit_call_id, run_id, thread_id, tool_call_id,
             tool_name, phase, occurred_at, duration_ms,
             arguments, result, error, authorization_context)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    def __init__(self, database_url: str, timeout_s: int = 5):
        if not database_url:
            raise ValueError("MIDAS_AUDIT_DATABASE_URL must be configured")
        if timeout_s < 1:
            raise ValueError("Audit timeout must be positive")
        self.database_url = database_url
        self.connection_options = {
            "connect_timeout": timeout_s,
            "autocommit": True,
            "options": (
                f"-c statement_timeout={timeout_s * 1000} "
                f"-c lock_timeout={timeout_s * 1000}"
            ),
            "application_name": "midas-audit",
        }
        self.timeout_s = timeout_s

    @staticmethod
    def _parameters(event):
        return (
            event["event_id"], event["audit_call_id"], event["run_id"],
            event["thread_id"], event["tool_call_id"], event["tool_name"],
            event["phase"], event["occurred_at"], event.get("duration_ms"),
            Jsonb(event["arguments"]),
            Jsonb(event["result"]) if event.get("result") is not None else None,
            Jsonb(event["error"]) if event.get("error") is not None else None,
            Jsonb(event["authorization"]) if event.get("authorization") is not None else None,
        )

    def append(self, event):
        with psycopg.connect(self.database_url, **self.connection_options) as conn:
            conn.execute(self.INSERT, self._parameters(event))

    async def aappend(self, event):
        async def insert():
            async with await psycopg.AsyncConnection.connect(
                self.database_url, **self.connection_options
            ) as conn:
                await conn.execute(self.INSERT, self._parameters(event))
        await asyncio.wait_for(insert(), timeout=self.timeout_s * 2)

    async def acheck(self):
        """Verify that the audit schema and permissions are in place."""
        async with await psycopg.AsyncConnection.connect(
            self.database_url, **self.connection_options
        ) as conn:
            cursor = await conn.execute(
                "SELECT has_table_privilege(current_user, "
                "'midas_audit.tool_events', 'INSERT')"
            )
            if not (await cursor.fetchone())[0]:
                raise AuditPersistenceError("The audit role lacks INSERT permission")
            cursor = await conn.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_attribute "
                "WHERE attrelid = 'midas_audit.tool_events'::regclass "
                "AND attname = 'authorization_context' AND NOT attisdropped)"
            )
            if not (await cursor.fetchone())[0]:
                raise AuditPersistenceError(
                    "Apply audit_schema.sql before starting the agent"
                )


# ---------------------------------------------------------------------------
# ToolAuditMiddleware: wrap every tool call with durable audit records
# ---------------------------------------------------------------------------

class ToolAuditMiddleware(AgentMiddleware):
    """Record request and outcome events; never silently discard write failures.

    Lifecycle per tool call:
        1. ``started`` event written before dispatch.
        2. Tool handler executes.
        3. Terminal event written: ``returned``, ``rejected``, ``tool_error``,
           ``exception``, or ``cancelled``.

    If any audit write fails, the middleware sets a persistent failure flag
    and blocks all subsequent tool calls until the agent is restarted.
    """

    state_schema = AuditState

    def __init__(self, audit_log, context_provider=None):
        super().__init__()
        self.audit_log = audit_log
        self.context_provider = context_provider
        self._failed = threading.Event()

    def _ensure_available(self):
        if self._failed.is_set():
            raise AuditPersistenceError(
                "Audit storage failed; this agent must be restarted after recovery"
            )

    def _append(self, event):
        self._ensure_available()
        try:
            self.audit_log.append(event)
        except Exception:
            self._failed.set()
            raise AuditPersistenceError(
                "Audit persistence failed; further tool calls are disabled"
            ) from None

    async def _aappend(self, event):
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

    # -- Agent lifecycle hooks -----------------------------------------------

    def before_agent(self, state, runtime):
        self._ensure_available()
        return {"midas_audit_run_id": str(uuid4())}

    async def abefore_agent(self, state, runtime):
        return self.before_agent(state, runtime)

    # -- Context extraction --------------------------------------------------

    @staticmethod
    def _context(state, runtime):
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
                configurable.get("thread_id")
                or metadata.get("thread_id")
                or ""
            ) or None,
        }

    def _call(self, tool_call, state, runtime):
        arguments = normalize(tool_call.get("args", {}))
        secrets = secret_values(arguments)
        return {
            **self._context(state, runtime),
            "audit_call_id": str(uuid4()),
            "tool_call_id": str(tool_call.get("id") or "") or None,
            "tool_name": tool_call["name"],
            "arguments": redact(arguments, secrets),
            "authorization": (
                redact(self.context_provider(runtime), secrets)
                if self.context_provider else None
            ),
        }, secrets

    @staticmethod
    def _event(call, phase, **fields):
        return {
            **call,
            "event_id": str(uuid4()),
            "phase": phase,
            "occurred_at": datetime.now(timezone.utc),
            **fields,
        }

    # -- Model output recording (proposed tool calls) ------------------------

    def _intent_events(self, state, runtime):
        messages = state.get("messages", [])
        for position in range(len(messages) - 1, -1, -1):
            message = messages[position]
            if getattr(message, "type", None) != "ai":
                continue
            returned = {
                item.tool_call_id: item
                for item in messages[position + 1:]
                if getattr(item, "type", None) == "tool"
            }
            for tool_call in getattr(message, "tool_calls", []):
                call, secrets = self._call(tool_call, state, runtime)
                response = returned.get(tool_call.get("id"))
                phase = "resolved_before_dispatch" if response is not None else "proposed"
                yield self._event(call, phase, result=redact(response, secrets))
            break

    def after_model(self, state, runtime):
        for event in self._intent_events(state, runtime):
            self._append(event)
        return None

    async def aafter_model(self, state, runtime):
        for event in self._intent_events(state, runtime):
            await self._aappend(event)
        return None

    # -- Outcome classification ----------------------------------------------

    @staticmethod
    def _outcome(result):
        artifact = getattr(result, "artifact", None)
        if isinstance(artifact, dict) and artifact.get("midas_audit_outcome") == "rejected":
            return "rejected"
        if getattr(result, "status", None) == "error":
            return "tool_error"
        content = getattr(result, "content", result)
        if isinstance(content, str):
            try:
                payload = json.loads(content)
            except (ValueError, TypeError):
                payload = None
            if isinstance(payload, dict) and (
                payload.get("status") == "error" or payload.get("isError") is True
            ):
                return "tool_error"
            if content.startswith((
                "Error:", "Error during ", "Execution failed",
                "SSH Authentication failed", "SSH connection failed",
                "SSH connection succeeded but command execution had errors:",
            )):
                return "tool_error"
        return "returned"

    # -- Synchronous tool-call wrapper ---------------------------------------

    def wrap_tool_call(self, request, handler):
        call, secrets = self._call(
            request.tool_call, request.runtime.state, request.runtime,
        )
        self._append(self._event(call, "started"))
        self._ensure_available()
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
                call, phase,
                duration_ms=(time.perf_counter() - started) * 1000,
                error=redact(
                    {"type": type(error).__name__, "message": str(error)}, secrets,
                ),
            ))
            raise
        self._append(self._event(
            call, self._outcome(result),
            duration_ms=(time.perf_counter() - started) * 1000,
            result=redact(result, secrets),
        ))
        return result

    # -- Asynchronous tool-call wrapper --------------------------------------

    async def awrap_tool_call(self, request, handler):
        call, secrets = self._call(
            request.tool_call, request.runtime.state, request.runtime,
        )
        await self._aappend(self._event(call, "started"))
        self._ensure_available()
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
                call, phase,
                duration_ms=(time.perf_counter() - started) * 1000,
                error=redact(
                    {"type": type(error).__name__, "message": str(error)}, secrets,
                ),
            ))
            raise
        await self._aappend(self._event(
            call, self._outcome(result),
            duration_ms=(time.perf_counter() - started) * 1000,
            result=redact(result, secrets),
        ))
        return result

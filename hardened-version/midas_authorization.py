"""Default-deny tool authorization using trusted invocation context.

Every tool call is checked against a static policy loaded at startup.
The policy declares which principals may invoke which tools, on which
hosts, and for which services.  Calls not explicitly granted are denied.
The model never supplies identity or credentials; these are injected by
the authenticated application context.
"""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from langchain.agents.middleware import AgentMiddleware
from langchain.messages import ToolMessage
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

# ---------------------------------------------------------------------------
# Allowlisted SSH operations — the only remote commands the agent may issue.
# ---------------------------------------------------------------------------

SSH_OPERATIONS = frozenset({
    "get_service_status",
    "read_service_logs",
    "list_listening_ports",
    "list_processes",
})

DISABLED_TOOLS = frozenset({"ssh_tool", "task"})

Identifier = Annotated[
    str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
]
Operation = Literal[
    "get_service_status", "read_service_logs", "list_listening_ports", "list_processes"
]


@dataclass(frozen=True)
class AuthorizationContext:
    """Supplied by the authenticated application; never derived from model input."""
    principal_id: str


# ---------------------------------------------------------------------------
# Policy data model (Pydantic, extra="forbid")
# ---------------------------------------------------------------------------

class PolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SSHHost(PolicyModel):
    address: Annotated[str, Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9:.\-]+$")]
    username: Identifier
    port: Annotated[int, Field(strict=True, ge=1, le=65535)] = 22
    known_hosts: Annotated[str, Field(min_length=1)]
    key_filename: Annotated[str, Field(min_length=1)] | None = None
    password_env: Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")] | None = None
    services: dict[
        Identifier,
        Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.@:\-]*\.service$")],
    ] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_credentials(self):
        if (self.key_filename is None) == (self.password_env is None):
            raise ValueError("Configure exactly one SSH key_filename or password_env")
        for filename in (self.known_hosts, self.key_filename):
            if filename is not None and not Path(filename).is_absolute():
                raise ValueError("SSH credential and known-hosts paths must be absolute")
        return self


class HostGrant(PolicyModel):
    """Per-host allowlist: which operations and services a principal may access."""
    operations: frozenset[Operation]
    services: frozenset[Identifier] = frozenset()
    max_log_lines: Annotated[int, Field(strict=True, ge=1, le=2000)] = 200


class PrincipalGrant(PolicyModel):
    """Per-principal allowlist: which tools and host grants are permitted."""
    tools: frozenset[Identifier] = frozenset()
    hosts: dict[Identifier, HostGrant] = Field(default_factory=dict)


class AuthorizationPolicy(PolicyModel):
    """Top-level policy: hosts inventory + principal grants.

    Validated at load time: every host reference in a principal grant must
    resolve to a declared host, and every service reference must exist on
    that host.
    """
    version: Identifier
    hosts: dict[Identifier, SSHHost]
    principals: dict[Identifier, PrincipalGrant]

    @model_validator(mode="after")
    def validate_references(self):
        for grant in self.principals.values():
            if grant.tools & (DISABLED_TOOLS | SSH_OPERATIONS):
                raise ValueError(
                    "SSH operations require host grants; raw SSH and delegation are disabled"
                )
            for host_id, host_grant in grant.hosts.items():
                if host_id not in self.hosts:
                    raise ValueError("A principal references an unknown host")
                if not host_grant.services <= self.hosts[host_id].services.keys():
                    raise ValueError("A principal references an unknown service")
        return self

    @classmethod
    def load(cls, filename):
        if not filename:
            raise ValueError("MIDAS_AUTHORIZATION_POLICY must be configured")
        return cls.model_validate_json(Path(filename).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Argument schemas for SSH operations (validated before authorization check)
# ---------------------------------------------------------------------------

class HostArguments(PolicyModel):
    host_id: Identifier


class ServiceArguments(HostArguments):
    service_id: Identifier


class LogArguments(ServiceArguments):
    max_lines: Annotated[int, Field(strict=True, ge=1, le=2000)] = 200


ARGUMENT_SCHEMAS = {
    "get_service_status": ServiceArguments,
    "read_service_logs": LogArguments,
    "list_listening_ports": HostArguments,
    "list_processes": HostArguments,
}


class AuthorizationDenied(ValueError):
    """A stable policy reason; never reflects untrusted arguments or credentials."""
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------------------
# Authorizer: default-deny check against the loaded policy
# ---------------------------------------------------------------------------

class ToolAuthorizer:
    """Check every tool call against the static authorization policy."""

    def __init__(self, policy):
        self._policy = policy.model_copy(deep=True)
        canonical = json.dumps(
            self._policy.model_dump(), default=sorted, sort_keys=True, separators=(",", ":"),
        )
        self.policy_version = self._policy.version
        self.policy_sha256 = hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def principal_id(runtime):
        context = getattr(runtime, "context", None)
        if isinstance(context, AuthorizationContext):
            return context.principal_id if isinstance(context.principal_id, str) else None
        return None

    def audit_context(self, runtime):
        """Return authorization metadata for inclusion in audit records."""
        return {
            "principal_id": self.principal_id(runtime),
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
        }

    def authorize(self, tool_name, arguments, runtime):
        """Return parsed arguments if authorized; raise AuthorizationDenied otherwise."""
        principal_id = self.principal_id(runtime)
        if not principal_id:
            raise AuthorizationDenied("missing_trusted_identity")
        grant = self._policy.principals.get(principal_id)
        if grant is None:
            raise AuthorizationDenied("unknown_principal")
        if tool_name in DISABLED_TOOLS:
            raise AuthorizationDenied("tool_disabled")
        if tool_name not in SSH_OPERATIONS:
            if tool_name not in grant.tools:
                raise AuthorizationDenied("tool_not_granted")
            return None
        try:
            parsed = ARGUMENT_SCHEMAS[tool_name].model_validate(arguments, strict=True)
        except ValidationError:
            raise AuthorizationDenied("invalid_arguments") from None
        host_grant = grant.hosts.get(parsed.host_id)
        if host_grant is None:
            raise AuthorizationDenied("host_not_granted")
        if tool_name not in host_grant.operations:
            raise AuthorizationDenied("operation_not_granted")
        if isinstance(parsed, ServiceArguments) and parsed.service_id not in host_grant.services:
            raise AuthorizationDenied("service_not_granted")
        if isinstance(parsed, LogArguments) and parsed.max_lines > host_grant.max_log_lines:
            raise AuthorizationDenied("log_limit_exceeded")
        return parsed

    def ssh_target(self, tool_name, arguments, runtime):
        """Authorize and return the resolved SSH host + parsed arguments."""
        parsed = self.authorize(tool_name, arguments, runtime)
        if parsed is None:
            raise AuthorizationDenied("not_a_diagnostic_operation")
        return self._policy.hosts[parsed.host_id].model_copy(deep=True), parsed


# ---------------------------------------------------------------------------
# Middleware: intercept every tool dispatch and enforce authorization
# ---------------------------------------------------------------------------

class ToolAuthorizationMiddleware(AgentMiddleware):
    """Authorize every dispatched tool call; no implicit grants or model-provided identity."""

    def __init__(self, authorizer):
        super().__init__()
        self.authorizer = authorizer

    def _check(self, request):
        try:
            self.authorizer.authorize(
                request.tool_call["name"],
                request.tool_call.get("args"),
                request.runtime,
            )
        except AuthorizationDenied as error:
            return ToolMessage(
                content=f"Authorization denied: {error.reason}. Do not retry through another tool.",
                tool_call_id=request.tool_call["id"],
                status="error",
                artifact={
                    "midas_audit_outcome": "rejected",
                    "authorization": {
                        **self.authorizer.audit_context(request.runtime),
                        "decision": "deny",
                        "reason": error.reason,
                    },
                },
            )
        return None

    def wrap_tool_call(self, request, handler):
        rejection = self._check(request)
        if rejection is not None:
            return rejection
        return handler(request)

    async def awrap_tool_call(self, request, handler):
        rejection = self._check(request)
        if rejection is not None:
            return rejection
        return await handler(request)

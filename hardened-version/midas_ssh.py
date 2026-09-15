"""Allowlist-only SSH diagnostics: fixed command templates, no model-supplied shell strings."""

import os
import shlex
import time

import paramiko
from langchain.tools import ToolRuntime, tool

if __package__:
    from .midas_authorization import AuthorizationContext
else:
    from midas_authorization import AuthorizationContext

# ---------------------------------------------------------------------------
# Allowlist: only these four operations can be executed over SSH.
# Each maps to a fixed command template with no user-supplied shell fragments.
# ---------------------------------------------------------------------------

ALLOWED_OPERATIONS = frozenset({
    "get_service_status",
    "read_service_logs",
    "list_listening_ports",
    "list_processes",
})


def diagnostic_command(operation, target, arguments):
    """Build an SSH command string from a fixed allowlist of diagnostic operations.

    Every returned command is constructed from literal executable paths and
    validated arguments; the model never supplies raw shell text.  Operations
    outside the allowlist raise ``ValueError`` before any SSH connection is
    attempted.
    """
    if operation not in ALLOWED_OPERATIONS:
        raise ValueError(f"Operation '{operation}' is not in the SSH allowlist")

    environment = ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C"]

    if operation == "get_service_status":
        command = [
            "/usr/bin/systemctl", "--no-pager", "--plain", "show",
            "--property=Id,LoadState,ActiveState,SubState,MainPID", "--",
            target.services[arguments.service_id],
        ]
    elif operation == "read_service_logs":
        command = [
            "/usr/bin/journalctl", "--no-pager", "--output=short-iso",
            f"--lines={arguments.max_lines}",
            f"--unit={target.services[arguments.service_id]}",
        ]
    elif operation == "list_listening_ports":
        command = ["/usr/bin/ss", "--listening", "--numeric", "--tcp", "--udp"]
    elif operation == "list_processes":
        command = ["/usr/bin/ps", "-eo", "pid,ppid,comm", "--no-headers"]
    else:
        raise ValueError(f"Operation '{operation}' is not in the SSH allowlist")

    return shlex.join(environment + command)


class SSHDiagnosticExecutor:
    """Execute allowlisted diagnostic commands over SSH with bounded output."""

    def __init__(self, authorizer, timeout_s=15, max_output_bytes=65536):
        if timeout_s <= 0 or max_output_bytes < 1:
            raise ValueError("SSH timeout and output limit must be positive")
        self.authorizer = authorizer
        self.timeout_s = timeout_s
        self.max_output_bytes = max_output_bytes

    def _read_output(self, channel):
        stdout = bytearray()
        stderr = bytearray()
        deadline = time.monotonic() + self.timeout_s
        error_code = None
        exit_status = None
        while True:
            if time.monotonic() >= deadline:
                error_code = "execution_timeout"
                break
            for ready, receive, output in (
                (channel.recv_ready, channel.recv, stdout),
                (channel.recv_stderr_ready, channel.recv_stderr, stderr),
            ):
                if ready():
                    chunk = receive(4096)
                    remaining = self.max_output_bytes - len(stdout) - len(stderr)
                    output.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        error_code = "output_limit_exceeded"
                        break
            if error_code:
                break
            if (channel.exit_status_ready()
                    and not channel.recv_ready()
                    and not channel.recv_stderr_ready()):
                exit_status = channel.recv_exit_status()
                break
            time.sleep(0.01)
        return {
            "status": "ok" if error_code is None and exit_status == 0 else "error",
            "exit_status": exit_status,
            "error_code": error_code or ("nonzero_exit" if exit_status != 0 else None),
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
        }

    def execute(self, operation, arguments, runtime):
        target, parsed = self.authorizer.ssh_target(operation, arguments, runtime)
        command = diagnostic_command(operation, target, parsed)
        credentials = {}
        if target.password_env is not None:
            password = os.environ.get(target.password_env)
            if not password:
                return {"status": "error", "error_code": "missing_ssh_credential"}
            credentials["password"] = password
        else:
            credentials["key_filename"] = target.key_filename
        try:
            with paramiko.SSHClient() as client:
                client.load_host_keys(target.known_hosts)
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
                client.connect(
                    target.address, port=target.port, username=target.username,
                    timeout=self.timeout_s, auth_timeout=self.timeout_s,
                    banner_timeout=self.timeout_s,
                    allow_agent=False, look_for_keys=False, **credentials,
                )
                stdin, stdout, stderr = client.exec_command(
                    command, timeout=self.timeout_s, get_pty=False,
                )
                stdin.close()
                try:
                    result = self._read_output(stdout.channel)
                finally:
                    stdout.channel.close()
                return {"operation": operation, "host_id": parsed.host_id, **result}
        except (OSError, paramiko.SSHException, ValueError) as error:
            return {
                "status": "error",
                "error_code": "ssh_transport_error",
                "error_type": type(error).__name__,
            }


def create_ssh_diagnostic_tools(authorizer):
    """Expose the four allowlisted SSH diagnostic operations as LangChain tools."""
    executor = SSHDiagnosticExecutor(authorizer)

    @tool
    def get_service_status(
        host_id: str, service_id: str,
        runtime: ToolRuntime[AuthorizationContext],
    ) -> dict:
        """Read an authorized service's state by configured host and service IDs."""
        return executor.execute(
            "get_service_status",
            {"host_id": host_id, "service_id": service_id},
            runtime,
        )

    @tool
    def read_service_logs(
        host_id: str, service_id: str,
        runtime: ToolRuntime[AuthorizationContext],
        max_lines: int = 200,
    ) -> dict:
        """Read bounded recent logs for an authorized service."""
        return executor.execute(
            "read_service_logs",
            {"host_id": host_id, "service_id": service_id, "max_lines": max_lines},
            runtime,
        )

    @tool
    def list_listening_ports(
        host_id: str,
        runtime: ToolRuntime[AuthorizationContext],
    ) -> dict:
        """Read numeric TCP/UDP listening sockets on an authorized host."""
        return executor.execute("list_listening_ports", {"host_id": host_id}, runtime)

    @tool
    def list_processes(
        host_id: str,
        runtime: ToolRuntime[AuthorizationContext],
    ) -> dict:
        """Read process IDs, parent IDs and executable names on an authorized host."""
        return executor.execute("list_processes", {"host_id": host_id}, runtime)

    return [get_service_status, read_service_logs, list_listening_ports, list_processes]

"""One approved MCP discovery over pipes in the normal unprivileged sandbox.

Only server/discover and tools/list are sent. No callbacks, restart, protocol-era
fallback, tool invocation, credentials or network. Result codes describe this
adapter operation; the separately reported server code is never verification.
"""

import hashlib
import os
import selectors
import signal
import subprocess
import time

from mano_protocol.actions import canonical
from mano_protocol.mcp import LINE_LIMIT, VERSION, WIRE_LIMIT, Discovery

from .delegate_home import Home
from .runner import OUTPUT_LIMIT, ProcessResult
from .sandbox import command


def run(workspace_fd, cwd_fd, argv, *, timeout, revoked, protocol_version):
    if (
        protocol_version != VERSION
        or type(timeout) is not int
        or not 1 <= timeout <= 300
        or not callable(revoked)
    ):
        raise ValueError("Explicit supported MCP version, deadline and observer required")

    def stopped():
        value = revoked()
        if type(value) is not bool:
            raise ValueError("Invalid MCP revocation observer")
        return value

    if stopped():
        return ProcessResult("revoked", 1, b"", b"")
    conversation = Discovery()
    with Home(argv) as home:
        if home.name is not None:
            raise ValueError("Coding delegate profiles are not MCP server profiles")
        args = command(workspace_fd, cwd_fd, argv, home=home, read_only=True)
        if stopped():
            return ProcessResult("revoked", 1, b"", b"")
        process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            close_fds=True,
            pass_fds=(workspace_fd, cwd_fd),
            start_new_session=True,
        )
    deadline = time.monotonic() + timeout
    reason, protocol_error = "completed", False
    buffer, diagnostics = bytearray(), bytearray()
    wire_hash = hashlib.sha256()
    wire_count = input_count = 0
    input_pending = b""
    stdin_open = True
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdin, process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                if stopped():
                    reason = "revoked"
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = "timed-out"
                    break
                if stdin_open and not input_pending and conversation.next_packet is not None:
                    input_pending, conversation.next_packet = conversation.next_packet, None
                    input_count += len(input_pending)
                    if input_count > 8192:
                        protocol_error = True
                        break
                    selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
                if stdin_open and conversation.done and not input_pending:
                    process.stdin.close()
                    stdin_open = False
                for key, _ in selector.select(min(remaining, 0.1)):
                    if key.data == "stdin":
                        try:
                            count = os.write(process.stdin.fileno(), input_pending)
                        except BlockingIOError:
                            continue
                        except BrokenPipeError:
                            protocol_error = True
                            break
                        if count <= 0:
                            protocol_error = True
                            break
                        input_pending = input_pending[count:]  # Never resend delivered bytes.
                        if not input_pending:
                            selector.unregister(process.stdin)
                            conversation.sent()
                        continue
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        if key.data == "stdout" and (buffer or not conversation.done):
                            protocol_error = True
                            break
                        continue
                    if key.data == "stderr":
                        available = OUTPUT_LIMIT - len(diagnostics)
                        diagnostics.extend(chunk[:available])
                        if len(chunk) > available:
                            reason = "output-limit"
                            break
                    else:
                        wire_hash.update(chunk)
                        wire_count += len(chunk)
                        if wire_count > WIRE_LIMIT:
                            reason = "output-limit"
                            break
                        buffer.extend(chunk)
                        while b"\n" in buffer:
                            line, _, rest = buffer.partition(b"\n")
                            buffer = bytearray(rest)
                            try:
                                conversation.accept(bytes(line))
                            except (ValueError, TypeError, KeyError, RecursionError):
                                protocol_error = True
                                break
                        if len(buffer) > LINE_LIMIT:
                            reason = "output-limit"
                            break
                    if protocol_error:
                        break
                if reason != "completed" or protocol_error:
                    break
            while reason == "completed" and not protocol_error and process.poll() is None:
                if stopped():
                    reason = "revoked"
                    break
                if time.monotonic() >= deadline:
                    reason = "timed-out"
                    break
                time.sleep(0.01)
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=5)
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
    if reason == "completed" and not protocol_error and process.returncode == 0:
        try:
            result = conversation.manifest(server_return_code=process.returncode)
            return ProcessResult("completed", 0, canonical(result).encode(), bytes(diagnostics))
        except (ValueError, TypeError, KeyError, RecursionError):
            protocol_error = True
    result = dict(
        schema_version="1.0",
        status="failed",
        protocol_version=VERSION,
        failure="protocol-error" if protocol_error else reason,
        server_return_code=process.returncode,
        wire_sha256=wire_hash.hexdigest(),
        untrusted=True,
        invocation_authorized=False,
    )
    return ProcessResult(reason, 1, canonical(result).encode(), bytes(diagnostics))

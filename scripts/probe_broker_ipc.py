#!/usr/bin/env python3
"""Real Linux request-channel identity attacks; fixed disposable guest only."""

import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

from mano_broker.ipc import serve_connection
from mano_broker.protocol import canonical
from mano_broker.state import State

DIRECTORY = Path("/var/lib/mano-broker/phase1-ipc-probe")
SOCKET = Path("/run/mano-phase1-ipc-probe.sock")
assert os.geteuid() == 0
assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
    "kvm",
    "qemu",
}
assert not DIRECTORY.exists() and not SOCKET.exists()
state = State(DIRECTORY)
listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
try:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    listener.settimeout(5)
    listener.bind(str(SOCKET))
    # Reachable by attack identities deliberately: prove broker auth independently of DAC.
    SOCKET.chmod(0o666)
    listener.listen(8)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    task = state.create_task(
        human_uid=1002,
        caller_uid=1004,
        mode="supervised",
        resource_id="a" * 32,
        classification="internal",
        boot_id=boot,
    )
    grant = state.issue_grant(
        task,
        approved_human_uid=1002,
        approved_args={"path": "file"},
        capability="files.read",
        resource_id="a" * 32,
        expires=time.monotonic() + 120,
        max_count=2,
        memory_bytes=1024**2,
        pids=4,
        cpu_percent=10,
        max_timeout_seconds=10,
    )
    body = dict(
        schema_version="1.0",
        task_id=task,
        grant_id=grant,
        capability="files.read",
        resource_id="a" * 32,
        args={"path": "file"},
        idempotency_key="fixed-ci-read",
        reason="IPC probe",
    )
    proposal = dict(schema_version="1.0", operation="propose", body=body)
    client = """import array,json,os,socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);s.settimeout(5);s.connect(sys.argv[1])
packet=sys.stdin.buffer.read();mode=sys.argv[2]
if mode=='handoff':
 pid=os.fork()
 if pid:
  _,status=os.waitpid(pid,0);sys.exit(os.waitstatus_to_exitcode(status))
if mode=='fd':
 fd=os.open('/dev/null',os.O_RDONLY)
 s.sendmsg([packet],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))]);os.close(fd)
else:s.sendall(packet)
print(s.recv(65536).decode());s.close()
"""
    cases = []

    def exchange(actor, packet, mode="normal"):
        before = len(list(Path("/proc/self/fd").iterdir()))
        process = subprocess.Popen(
            ["/usr/sbin/runuser", "-u", actor, "--", "python3", "-c", client, str(SOCKET), mode],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        process.stdin.write(packet)
        process.stdin.close()
        process.stdin = None
        try:
            connection, _ = listener.accept()
            with connection:
                serve_connection(state, connection, boot_id=boot)
            stdout, stderr = process.communicate(timeout=10)
            assert process.returncode == 0, stderr.decode()
            response = json.loads(stdout)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        assert len(list(Path("/proc/self/fd").iterdir())) == before, "FD leak"
        return response

    positive = exchange("mano-worker", canonical(proposal).encode())
    assert positive["ok"] and positive["fresh"] and positive["action"]["state"] == "intent"
    assert positive["action"]["verified"] == 0
    replay = exchange("mano-worker", canonical(proposal).encode())
    assert (
        replay["ok"] and not replay["fresh"] and replay["action"]["id"] == positive["action"]["id"]
    )
    query = dict(
        schema_version="1.0",
        operation="status",
        body=dict(task_id=task, action_id=positive["action"]["id"]),
    )
    assert exchange("mano-worker", canonical(query).encode())["ok"]
    attacks = [
        (
            "changed-approved-target",
            "mano-worker",
            proposal | {"body": body | {"args": {"path": "other"}, "idempotency_key": "altered"}},
            "normal",
        ),
        ("wrong-agent", "mano-agent", proposal, "normal"),
        ("wrong-core", "mano-core", proposal, "normal"),
        ("wrong-human", "mano-human", proposal, "normal"),
        ("cross-caller-status", "mano-core", query, "normal"),
        ("forged-uid", "mano-worker", proposal | {"caller_uid": 1004}, "normal"),
        ("grant-mint", "mano-worker", proposal | {"operation": "issue_grant"}, "normal"),
        ("self-verify", "mano-worker", proposal | {"operation": "verify"}, "normal"),
        ("stop-control", "mano-worker", proposal | {"operation": "emergency_stop"}, "normal"),
        ("inherited-connection", "mano-worker", proposal, "handoff"),
        ("passed-fd", "mano-worker", proposal, "fd"),
    ]
    for name, actor, packet, mode in attacks:
        response = exchange(actor, canonical(packet).encode(), mode)
        assert response == dict(schema_version="1.0", ok=False, error="denied"), (name, response)
        cases.append({"name": name, "actor": actor, "denied": True})
    for name, packet in [
        ("oversize", b"x" * 65537),
        ("malformed", b"{"),
        ("deep-json", b"[" * 1500 + b"0" + b"]" * 1500),
    ]:
        assert exchange("mano-worker", packet) == dict(
            schema_version="1.0", ok=False, error="denied"
        )
        cases.append({"name": name, "actor": "mano-worker", "denied": True})
    assert state.db.execute("SELECT count(*) FROM actions").fetchone()[0] == 1
    assert state.db.execute("SELECT used FROM grants").fetchone()[0] == 1
    print(
        json.dumps(
            dict(
                scope="request transport; no executor or PAM control integrated",
                credentials="SO_PEERCRED plus per-message SCM_CREDENTIALS",
                positive_proposal_and_status=True,
                idempotent_replay=True,
                attacks=cases,
                one_reservation_only=True,
                no_received_fd_leak=True,
                model_connected=False,
                production_execution_authorized=False,
            ),
            indent=2,
        )
    )
finally:
    listener.close()
    state.close()
    SOCKET.unlink(missing_ok=True)
    shutil.rmtree(DIRECTORY)

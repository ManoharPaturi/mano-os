#!/usr/bin/env python3
"""Real delegated service cgroup custody in the disposable VM, no task argv."""

import base64
import ctypes
import grp
import json
import os
import pwd
import shutil
import subprocess
import sys
import time
from pathlib import Path

from mano_broker.cgroups import ROOT, Manager
from mano_broker.credentials import drop
from mano_broker.executor import Executor
from mano_broker.identities import LOCK, allocate_identity
from mano_broker.ipc import Peer
from mano_broker.launch_admission import LaunchAdmission
from mano_broker.launch_client import Client
from mano_broker.launch_controller import Controller, serve_control, serve_prepare
from mano_broker.launch_transport import PATHS, activated_listeners
from mano_broker.limits import Limits
from mano_broker.protocol import ActionRequest, Capability, Mode, canonical
from mano_broker.registry import Registry
from mano_broker.resources import LIBRARY
from mano_broker.sandbox import GUARD
from mano_broker.state import Denied, State
from mano_broker.workspaces import BASE, create_workspace

STATE = Path("/run/mano-delegation-ci")
JOURNAL = Path("/run/mano-journal-ci")
STOP_STATE = Path("/var/lib/mano-stopd")
STOP_NATIVE = Path("/usr/libexec/mano-stopd")
STOP_POLICY = Path("/etc/mano/human.uid")
STOP_UNITS = [Path("/etc/systemd/system") / name for name in (
    "mano-stopd.service", "mano-stopd.socket", "mano-stopd-control.socket", "mano-core.slice"
)]
CODE = Path("/usr/lib/mano-os")
UNIT_FILE = Path("/etc/systemd/system/mano-launcher.service")
SOCKET_UNITS = {name: Path(f"/etc/systemd/system/mano-launcher-{name}.socket") for name in PATHS}
TRANSPORT_DIR = Path("/run/mano-launcher")
assert os.geteuid() == 0
assert Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
    "kvm",
    "qemu",
}

if sys.argv[1:] == ["--inner"]:
    listeners = activated_listeners()
    for listener in listeners.values():
        listener.setblocking(False)

    def security_state(stage):
        fields = dict(
            line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
        )
        print(
            json.dumps(
                dict(
                    stage=stage,
                    pid=os.getpid(),
                    security={
                        name: fields[name].strip()
                        for name in (
                            "Uid",
                            "Gid",
                            "CapInh",
                            "CapPrm",
                            "CapEff",
                            "CapBnd",
                            "CapAmb",
                            "NoNewPrivs",
                            "Seccomp",
                        )
                    },
                )
            ),
            file=sys.stderr,
            flush=True,
        )

    security_state("manager-start")
    manager_security = dict(
        line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
    )
    assert int(manager_security["CapEff"].strip(), 16) == 0xC0
    assert int(manager_security["CapPrm"].strip(), 16) == 0xC0
    assert int(manager_security["CapBnd"].strip(), 16) == 0xC0
    assert int(manager_security["CapAmb"].strip(), 16) == 0x80
    account = json.loads((STATE / "identity.json").read_text())
    manager = Manager()
    first = manager.create("a" * 32)
    second = manager.create("b" * 32, Limits(64 * 1024**2, 16, 10))
    assert (second.path / "memory.max").read_text().strip() == "67108864"
    assert (second.path / "pids.max").read_text().strip() == "16"
    assert (second.path / "cpu.max").read_text().strip() == "10000 100000"
    try:
        manager.create("c" * 32)
    except Denied:
        pass
    else:
        raise AssertionError("Concurrent group quota not enforced")
    try:
        first.attach_root_child(os.getpid())
    except Denied:
        pass
    else:
        raise AssertionError("Arbitrary PID accepted")
    assert (first.path / "memory.max").read_text().strip() == "134217728"
    assert (first.path / "pids.max").read_text().strip() == "24"
    assert (first.path / "cpu.max").read_text().strip() == "20000 100000"
    assert (first.path / "memory.oom.group").read_text().strip() == "1"
    reader, writer = os.pipe()
    ready_reader, ready_writer = os.pipe()
    parent_pid = os.getpid()
    child = os.fork()
    if child == 0:
        os.close(writer)
        os.close(ready_reader)
        assert os.read(reader, 1) == b"g"
        security_state("child-before-drop")
        drop(action_id="a" * 32, caller_uid=account["uid"], parent_pid=parent_pid)
        security_state("child-after-user-drop")
        death_signal = ctypes.c_int()
        libc = ctypes.CDLL(None, use_errno=True)
        assert libc.prctl(2, ctypes.byref(death_signal), 0, 0, 0) == 0
        assert death_signal.value == 9
        child_security = dict(
            line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
        )
        assert all(
            int(child_security[name].strip(), 16) == 0
            for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")
        )
        assert child_security["NoNewPrivs"].strip() == "1"
        detached_reader, detached_writer = os.pipe()
        grandchild = os.fork()
        if grandchild == 0:
            os.close(detached_reader)
            os.setsid()
            os.write(detached_writer, b"d")
            os.close(detached_writer)
            time.sleep(60)
            os._exit(0)
        os.close(detached_writer)
        assert os.read(detached_reader, 1) == b"d"
        os.close(detached_reader)
        os.write(ready_writer, b"r")
        time.sleep(60)
        os._exit(0)
    os.close(reader)
    os.close(ready_writer)
    try:
        first.attach_root_child(child)
        assert str(child) in (first.path / "cgroup.procs").read_text().split()
        os.write(writer, b"g")
        os.close(writer)
        writer = -1
        assert os.read(ready_reader, 1) == b"r"
        members = set((first.path / "cgroup.procs").read_text().split())
        assert len(members) == 2 and str(child) in members
        detached_pid = int((members - {str(child)}).pop())
        assert os.getsid(detached_pid) == detached_pid
        assert first.populated()
        assert (
            Path(f"/proc/{child}/status").read_text().split("Uid:", 1)[1].splitlines()[0].split()
            == [str(account["uid"])] * 4
        )
        first.kill_and_close()
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == -9
        assert not first.path.exists()
        try:
            manager.create("a" * 32)
        except Denied:
            pass
        else:
            raise AssertionError("Closed action ID reused")
        second.kill_and_close()
        assert set((ROOT / "control" / "cgroup.procs").read_text().split()) == {str(os.getpid())}
        workspace = Path(account["workspace"])
        root_fd = os.open(workspace, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        cwd_fd = os.dup(root_fd)
        sequence = 0
        controller = Controller(manager)
        broker_account = pwd.getpwnam("mano-broker")
        operator_peer = Peer(os.getpid(), broker_account.pw_uid, broker_account.pw_gid)
        handles = {}

        def control(operation, job, **extra):
            return controller.dispatch(
                canonical(
                    dict(
                        schema_version="1.0",
                        operation=operation,
                        body=handles[job] | extra,
                    )
                ).encode(),
                peer=operator_peer,
            )

        def observe(name, *, contents=False):
            # Observe as the directory owner in a separate fixed-code process;
            # the supervisor has no DAC override and keeps its credentials.
            observation_r, observation_w = os.pipe()
            observer = os.fork()
            if observer == 0:
                try:
                    for entry in os.listdir("/proc/self/fd"):
                        fd = int(entry)
                        if fd not in {0, 1, 2, observation_w}:
                            try:
                                os.close(fd)
                            except OSError:
                                pass
                    broker = pwd.getpwnam("mano-broker")
                    os.setgroups([])
                    os.setgid(broker.pw_gid)
                    os.setuid(broker.pw_uid)
                    value = (
                        (workspace / name).read_text() if contents else (workspace / name).exists()
                    )
                    os.write(observation_w, json.dumps(value).encode())
                    os._exit(0)
                except BaseException:
                    os._exit(125)
            os.close(observation_w)
            packet = os.read(observation_r, 4096)
            os.close(observation_r)
            _, observer_status = os.waitpid(observer, 0)
            assert os.waitstatus_to_exitcode(observer_status) == 0
            return json.loads(packet)

        def prepare(source):
            global sequence
            sequence += 1
            request = ActionRequest.parse(
                canonical(
                    dict(
                        schema_version="1.0",
                        task_id="a" * 32,
                        grant_id="b" * 32,
                        resource_id="c" * 32,
                        capability="terminal.run",
                        args=dict(
                            argv=["/usr/bin/python3", "-c", source], cwd=".", timeout_seconds=10
                        ),
                        idempotency_key=f"operator-{sequence}",
                        reason="operator fixture; no broker grant",
                    )
                ).encode()
            )
            reply = controller.prepare(
                LaunchAdmission(
                    f"{sequence:032x}",
                    account["uid"],
                    request,
                    root_fd,
                    cwd_fd,
                    owner=operator_peer,
                )
            )
            job = controller.records[reply["job_id"]].child
            handles[job] = {name: reply[name] for name in ("instance_id", "job_id", "action_id")}
            return job

        def completed(job):
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                status = control("status", job)
                assert status["effect_verified"] is False
                result = job.result
                if job.closed:
                    assert job.state == "finished" and result is not None
                    return result
                time.sleep(0.01)
            job.cancel()
            raise AssertionError("Supervised child completion deadline")

        normal = prepare(
            "from pathlib import Path;Path('/workspace/started').write_text('1');print(42)"
        )
        assert normal.state == "prepared" and not observe("started")
        try:
            controller.dispatch(
                canonical(
                    dict(
                        schema_version="1.0",
                        operation="start",
                        body=handles[normal] | {"instance_id": "f" * 32},
                    )
                ).encode(),
                peer=operator_peer,
            )
        except Denied:
            pass
        else:
            raise AssertionError("Wrong controller instance accepted")
        control("start", normal)  # Synthetic operator peer, not a broker journal grant.
        try:
            control("start", normal)
        except Denied:
            pass
        else:
            raise AssertionError("Start replay accepted")
        observed = completed(normal)
        assert observed.return_code == 0 and observed.stdout.strip() == b"42", observed.stderr
        assert observe("started", contents=True) == "1"
        denied = prepare("from pathlib import Path;Path('/workspace/denied').write_text('bad')")
        try:
            denied.start(lambda: False)
        except Denied:
            pass
        else:
            raise AssertionError("False start authority accepted")
        assert denied.state == "not-started" and not observe("denied")
        expired = prepare("from pathlib import Path;Path('/workspace/expired').write_text('bad')")
        time.sleep(5.1)
        try:
            expired.start(lambda: True)
        except Denied:
            pass
        else:
            raise AssertionError("Expired prepared child started")
        assert expired.state == "not-started" and not observe("expired")
        large = prepare("import os;os.write(1,b'x'*65536);os.write(2,b'y'*65536)")
        control("start", large)
        big = completed(large)
        assert big.return_code == 0 and len(big.stdout) == len(big.stderr) == 65536
        piece = control("read_output", large, stream="stdout", offset=4096, length=4096)
        assert base64.b64decode(piece["data"]) == b"x" * 4096
        assert piece["eof"] is False and piece["effect_verified"] is False
        active = prepare(
            "import time;from pathlib import Path;"
            "Path('/workspace/active').write_text('1');time.sleep(60)"
        )
        control("start", active)
        deadline = time.monotonic() + 5
        while not observe("active") and time.monotonic() < deadline:
            time.sleep(0.01)
        assert observe("active")
        control("cancel", active)
        assert active.state == "unknown" and active.result is None
        before_fds = len(list(Path("/proc/self/fd").iterdir()))
        sequence += 1
        bad_request = ActionRequest.parse(
            canonical(
                dict(
                    schema_version="1.0",
                    task_id="a" * 32,
                    grant_id="b" * 32,
                    resource_id="c" * 32,
                    capability="terminal.run",
                    args=dict(argv=["/usr/bin/true"], cwd=".", timeout_seconds=5),
                    idempotency_key="bad-fd-fixture",
                    reason="operator failure fixture",
                )
            ).encode()
        )
        try:
            controller.prepare(
                LaunchAdmission(
                    f"{sequence:032x}", account["uid"], bad_request, -1, cwd_fd, owner=operator_peer
                )
            )
        except OSError:
            pass
        else:
            raise AssertionError("Invalid admission FD accepted")
        assert not manager.jobs
        assert len(list(Path("/proc/self/fd").iterdir())) == before_fds
        os.close(root_fd)
        os.close(cwd_fd)
        assert not manager.jobs
        proxy_report_r, proxy_report_w = os.pipe()
        server_pid = os.getpid()
        proxy = os.fork()
        if proxy == 0:
            try:
                for entry in os.listdir("/proc/self/fd"):
                    fd = int(entry)
                    if fd not in {0, 1, 2, proxy_report_w}:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                os.setgroups([])
                os.setgid(broker_account.pw_gid)
                os.setuid(broker_account.pw_uid)

                client = Client()

                def exchange(channel, envelope, with_fds=False):
                    rights = []
                    try:
                        if with_fds:
                            rights = [
                                os.open(workspace, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
                                for _ in range(2)
                            ]
                        result = client.exchange(channel, envelope, rights)
                        assert client.peer.pid == server_pid
                        return result
                    finally:
                        for fd in rights:
                            os.close(fd)

                def wire_prepare(action, source):
                    request = dict(
                        schema_version="1.0",
                        task_id="a" * 32,
                        grant_id="b" * 32,
                        resource_id="c" * 32,
                        capability="terminal.run",
                        args=dict(
                            argv=["/usr/bin/python3", "-c", source], cwd=".", timeout_seconds=10
                        ),
                        idempotency_key="wire-operator-" + action,
                        reason="real broker transport; operator fixture grant only",
                    )
                    reply = exchange(
                        "prepare",
                        dict(
                            schema_version="1.0",
                            operation="launch_task",
                            body=dict(action_id=action, caller_uid=account["uid"], request=request),
                        ),
                        True,
                    )
                    assert reply["ok"], reply
                    return {key: reply[key] for key in ("instance_id", "job_id", "action_id")}

                def wire_control(operation, handle, **extra):
                    return exchange(
                        "control",
                        dict(schema_version="1.0", operation=operation, body=handle | extra),
                    )

                one = wire_prepare("d" * 32, "print('wire-ok')")
                assert wire_control("start", one)["ok"]
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    state = wire_control("status", one)
                    if state.get("state") == "finished":
                        break
                    time.sleep(0.01)
                assert state["state"] == "finished" and state["return_code"] == 0
                output = wire_control("read_output", one, stream="stdout", offset=0, length=64)
                assert base64.b64decode(output["data"]).strip() == b"wire-ok"
                assert output["effect_verified"] is False
                running = wire_prepare("e" * 32, "import time;time.sleep(60)")
                assert wire_control("start", running)["ok"]
                concurrent = wire_prepare("f" * 32, "print('must-not-start')")
                assert wire_control("status", running)["state"] == "running"
                assert wire_control("cancel", concurrent)["state"] == "not-started"
                assert wire_control("cancel", running)["state"] == "unknown"
                journal = State(JOURNAL / "executor")
                registry = Registry()
                fd = os.open(workspace, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
                try:
                    resource_id = registry.register(fd, human_uid=1002,
                        caller_uid=account["uid"], boot_id="executor-fixture-boot")
                finally:
                    os.close(fd)
                task_id = journal.create_task(human_uid=1002, caller_uid=account["uid"],
                    mode=Mode.AUTO, resource_id=resource_id, classification="internal",
                    boot_id="executor-fixture-boot")
                registry.resources[resource_id].task_id = task_id
                executor = Executor(journal, registry, client, boot_id="executor-fixture-boot")

                def authorized(source, key):
                    args = dict(argv=["/usr/bin/python3", "-c", source], cwd=".",
                                timeout_seconds=10)
                    grant = journal.issue_grant(task_id, approved_human_uid=1002,
                        approved_args=args, capability=Capability.RUN, resource_id=resource_id,
                        expires=time.monotonic() + 30, max_count=1, memory_bytes=64 * 1024**2,
                        pids=16, cpu_percent=10, max_timeout_seconds=10)
                    request = ActionRequest.parse(canonical(dict(schema_version="1.0",
                        task_id=task_id, resource_id=resource_id, grant_id=grant,
                        capability="terminal.run", args=args, idempotency_key=key,
                        reason="operator approval fixture with actual journal coupling")).encode())
                    row, lease = registry.prepare(journal, request, caller_uid=account["uid"],
                        now=time.monotonic(), boot_id="executor-fixture-boot")
                    assert lease is not None
                    return row["id"]

                completed = authorized("print('journal-wire-ok')", "journal-once")
                executor.launch(completed)
                handle = executor.jobs[completed].copy()
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    result = executor.poll(completed)
                    if result["state"] == "finished":
                        break
                    time.sleep(0.01)
                row = journal.db.execute(
                    "SELECT * FROM actions WHERE id=?", (completed,)
                ).fetchone()
                assert row["state"] == "done" and row["verified"] == 0
                output = wire_control("read_output", handle, stream="stdout", offset=0, length=64)
                assert base64.b64decode(output["data"]).strip() == b"journal-wire-ok"
                try:
                    executor.launch(completed)
                except Denied:
                    pass
                else:
                    raise AssertionError("Journal action repeated")
                active = authorized("import time;time.sleep(60)", "journal-stop")
                executor.launch(active)
                handle = executor.jobs[active].copy()
                journal.emergency_stop()
                try:
                    executor.poll(active)
                except Denied:
                    pass
                else:
                    raise AssertionError("Stopped journal action reported success")
                assert wire_control("status", handle)["state"] == "unknown"
                assert journal.db.execute("SELECT state FROM actions WHERE id=?",
                                          (active,)).fetchone()[0] == "unknown"
                assert not registry.leases
                registry.close()
                journal.close()
                client.close()
                os.write(proxy_report_w, b"ok")
                os._exit(0)
            except BaseException:
                import traceback

                traceback.print_exc()
                os._exit(125)
        os.close(proxy_report_w)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            for name, listener in listeners.items():
                try:
                    connection, _ = listener.accept()
                except BlockingIOError:
                    continue
                with connection:
                    if name == "prepare":
                        serve_prepare(controller, connection)
                    else:
                        serve_control(controller, connection)
            controller.sweep()
            ended, proxy_status = os.waitpid(proxy, os.WNOHANG)
            if ended:
                assert os.waitstatus_to_exitcode(proxy_status) == 0
                break
            time.sleep(0.005)
        else:
            raise AssertionError("Persistent broker proxy deadline")
        assert os.read(proxy_report_r, 64) == b"ok"
        os.close(proxy_report_r)
        controller.close()
        for listener in listeners.values():
            listener.close()
        manager.close()
        assert not (ROOT / "control").exists()
        (STATE / "report.json").write_text(
            json.dumps(
                dict(
                    scope="delegated cgroup library in actual root service; no launch endpoint",
                    own_service_only=True,
                    manager_control_separated=True,
                    task_limits=dict(memory_bytes=134217728, pids=24, cpu_quota="20000 100000"),
                    placed_before_credential_drop=True,
                    task_uid=account["uid"],
                    allocated_identity_drop=True,
                    parent_death_signal_set=True,
                    detached_descendant_killed=True,
                    task_group_removed=True,
                    concurrent_quota_denied=True,
                    arbitrary_pid_denied=True,
                    action_reuse_denied=True,
                    manager_survived=True,
                    child_capability_sets_zero=True,
                    manager_capabilities="SETUID|SETGID; ambient SETUID only",
                    supervised_child=dict(
                        blocked_before_start=True,
                        exact_start_once=True,
                        denied_start_no_effect=True,
                        expired_preparation_no_effect=True,
                        failed_allocation_no_fd_or_group_leak=True,
                        operator_workspace_effect_observed=True,
                        both_64k_stream_report_drained=True,
                        active_cancel_unknown=True,
                        all_groups_removed=True,
                        broker_grant_integrated=False,
                        private_controller_instance_guard=True,
                        private_controller_start_once=True,
                        output_chunk_bounded=True,
                        controller_verified_flag_false=True,
                        operator_peer_metadata_synthetic=True,
                        real_persistent_broker_transport=True,
                        production_client_transport=True,
                        durable_journal_executor=True,
                        lower_grant_kernel_limits=True,
                        journal_stop_cancels_unknown=True,
                        executor_pam_authorization=False,
                        reply_creator_and_message_credentials=True,
                        minimum_capability_cwd_pin=True,
                        metadata_pin_preserves_running_child=True,
                    ),
                    no_task_argv_executed=False,
                    model_connected=False,
                ),
                indent=2,
            )
        )
    finally:
        if writer >= 0:
            os.close(writer)
        os.close(ready_reader)
    sys.exit(0)

assert not sys.argv[1:]
assert not STATE.exists() and not CODE.exists() and not UNIT_FILE.exists() and not LOCK.exists()
assert not BASE.exists() and not GUARD.exists()
assert not LIBRARY.exists() and not TRANSPORT_DIR.exists() and not JOURNAL.exists()
assert all(not path.exists() for path in SOCKET_UNITS.values())
assert not STOP_STATE.exists() and not STOP_NATIVE.exists() and not STOP_POLICY.exists()
assert all(not path.exists() for path in STOP_UNITS)
assert "mano-broker" not in {p.pw_name for p in pwd.getpwall()}
assert "mano-request" not in {g.gr_name for g in grp.getgrall()}
created = []
group_created = False
try:
    subprocess.run(["groupadd", "mano-request"], check=True)
    group_created = True
    subprocess.run(["useradd", "--system", "--no-create-home", "mano-broker"], check=True)
    created.append("mano-broker")
    identity = allocate_identity()
    created.append(identity.name)
    workspace, workspace_fd = create_workspace(human_uid=1002, caller_uid=identity.uid)
    os.close(workspace_fd)
    subprocess.run(
        [
            "cc",
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fstack-protector-strong",
            "-D_FORTIFY_SOURCE=2",
            "/opt/mano-lab/native/mano_sandbox_guard.c",
            "-lseccomp",
            "-Wl,-z,relro,-z,now",
            "-o",
            str(GUARD),
        ],
        check=True,
    )
    GUARD.chmod(0o555)
    LIBRARY.parent.mkdir(mode=0o755, exist_ok=True)
    subprocess.run(
        [
            "cc",
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fPIC",
            "-shared",
            "/opt/mano-lab/native/mano_resources.c",
            "-Wl,-z,relro,-z,now",
            "-o",
            str(LIBRARY),
        ],
        check=True,
    )
    LIBRARY.chmod(0o644)
    JOURNAL.mkdir(mode=0o700)
    broker = pwd.getpwnam("mano-broker")
    os.chown(JOURNAL, broker.pw_uid, broker.pw_gid)
    STOP_POLICY.parent.mkdir(mode=0o755, exist_ok=True)
    STOP_POLICY.write_text("1002\n")
    STOP_POLICY.chmod(0o600)
    subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
        "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "/opt/mano-lab/native/mano_stopd.c",
        *subprocess.check_output(["pkg-config", "--cflags", "--libs", "libsystemd"],
                                 text=True).split(), "-Wl,-z,relro,-z,now", "-o", str(STOP_NATIVE)],
        check=True)
    STOP_NATIVE.chmod(0o555)
    for unit in STOP_UNITS:
        shutil.copyfile(Path("/opt/mano-lab/packaging/systemd") / unit.name, unit)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "start", "mano-stopd.socket", "mano-stopd.service"], check=True)
    STATE.mkdir(mode=0o700)
    (STATE / "identity.json").write_text(
        json.dumps({"uid": identity.uid, "gid": identity.gid, "workspace": str(workspace)})
    )
    (STATE / "identity.json").chmod(0o600)
    CODE.mkdir(mode=0o755)
    shutil.copytree(
        "/opt/mano-lab/src/mano_broker",
        CODE / "mano_broker",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    shutil.copytree(
        "/opt/mano-lab/src/mano_lab",
        CODE / "mano_lab",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    shutil.copytree(
        "/opt/mano-lab/src/mano_protocol",
        CODE / "mano_protocol",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    shutil.copyfile(__file__, CODE / "probe.py")
    for file in CODE.rglob("*.py"):
        file.chmod(0o444)
    UNIT_FILE.write_text("""[Unit]
Description=Disposable mano delegated cgroup proof
Requires=mano-launcher-prepare.socket mano-launcher-control.socket
After=mano-launcher-prepare.socket mano-launcher-control.socket
[Service]
Type=exec
Sockets=mano-launcher-prepare.socket mano-launcher-control.socket
User=root
ExecStart=/usr/bin/python3 /usr/lib/mano-os/probe.py --inner
Environment=PYTHONPATH=/usr/lib/mano-os
Environment=PYTHONDONTWRITEBYTECODE=1
Delegate=cpu memory pids
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SETUID CAP_SETGID
AmbientCapabilities=CAP_SETUID
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectControlGroups=no
ReadWritePaths=/sys/fs/cgroup/system.slice/mano-launcher.service /run/mano-delegation-ci
ReadWritePaths=/var/lib/mano-workspaces /run/mano-journal-ci
MemoryMax=320M
TasksMax=64
CPUQuota=60%
KillMode=control-group
TimeoutStartSec=15
TimeoutStopSec=5
RuntimeMaxSec=45
""")
    for name, unit in SOCKET_UNITS.items():
        unit.write_text(f"""[Unit]
Description=Disposable private launcher {name} activation
[Socket]
ListenSequentialPacket={PATHS[name]}
Service=mano-launcher.service
SocketUser=mano-broker
SocketGroup=mano-broker
SocketMode=0600
DirectoryMode=0755
PassCredentials=yes
FileDescriptorName={name}
RemoveOnStop=yes
""")
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(
        ["systemctl", "start", *(p.name for p in SOCKET_UNITS.values()), "mano-launcher.service"],
        check=True,
    )
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if (STATE / "report.json").exists():
            break
        result = subprocess.check_output(
            ["systemctl", "show", "mano-launcher.service", "--property=Result", "--value"],
            text=True,
        ).strip()
        assert result == "success", result
        time.sleep(0.1)
    else:
        raise AssertionError("Delegated service report unavailable")
    subprocess.run(["systemctl", "stop", "mano-launcher.service",
                    *(p.name for p in SOCKET_UNITS.values())], check=True)
    packaging = Path("/opt/mano-lab/packaging/systemd")
    shutil.copyfile(packaging / UNIT_FILE.name, UNIT_FILE)
    for unit in SOCKET_UNITS.values():
        shutil.copyfile(packaging / unit.name, unit)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "start", *(p.name for p in SOCKET_UNITS.values()),
                    "mano-launcher.service"], check=True)
    daemon = subprocess.run(["/usr/bin/python3", "/opt/mano-lab/scripts/probe_launcher_service.py"],
                            check=False, capture_output=True, text=True, timeout=20)
    if daemon.returncode != 0:
        print(daemon.stderr, file=sys.stderr)
        raise AssertionError("Installed launcher client failed: " + str(daemon.returncode))
    report = json.loads((STATE / "report.json").read_text())
    report["production_daemon"] = json.loads(daemon.stdout)
    print(json.dumps(report, indent=2))
except BaseException:
    subprocess.run(
        ["journalctl", "-u", "mano-launcher.service", "--no-pager", "-n", "80"],
        stdout=sys.stderr,
        check=False,
    )
    raise
finally:
    subprocess.run(
        ["systemctl", "stop", "mano-launcher.service", *(p.name for p in SOCKET_UNITS.values()),
         *(p.name for p in STOP_UNITS)],
        check=False,
        capture_output=True,
    )
    for unit in STOP_UNITS:
        unit.unlink(missing_ok=True)
    STOP_NATIVE.unlink(missing_ok=True)
    STOP_POLICY.unlink(missing_ok=True)
    if STOP_STATE.exists():
        shutil.rmtree(STOP_STATE)
    stop_socket_dir = Path("/run/mano-stopd")
    if stop_socket_dir.exists():
        stop_socket_dir.rmdir()
    UNIT_FILE.unlink(missing_ok=True)
    for path in SOCKET_UNITS.values():
        path.unlink(missing_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], check=False, capture_output=True)
    subprocess.run(
        ["systemctl", "reset-failed", "mano-launcher.service"], check=False, capture_output=True
    )
    if CODE.exists():
        shutil.rmtree(CODE)
    if STATE.exists():
        shutil.rmtree(STATE)
    if JOURNAL.exists():
        shutil.rmtree(JOURNAL)
    if BASE.exists():
        shutil.rmtree(BASE)
    GUARD.unlink(missing_ok=True)
    LIBRARY.unlink(missing_ok=True)
    if TRANSPORT_DIR.exists():
        TRANSPORT_DIR.rmdir()

    for name in reversed(created):
        subprocess.run(["userdel", name], check=False, capture_output=True)
    if group_created:
        subprocess.run(["groupdel", "mano-request"], check=False, capture_output=True)
    LOCK.unlink(missing_ok=True)

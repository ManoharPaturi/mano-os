#!/usr/bin/env python3
"""Task-only X11 capability and actual namespace/role denial probes."""

import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from mano_lab.sandbox import ENV, require_patched


def run(argv, timeout=20):
    return subprocess.run(
        argv, env=ENV, text=True, capture_output=True, timeout=timeout, check=False
    )


def main():
    require_patched()
    marker = Path("/etc/mano-lab-disposable")
    if os.getuid() != 0 or not marker.is_file() or marker.read_text().strip() != "mano-phase0-ci":
        raise RuntimeError("Disposable guest supervisor required")
    if subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() not in {
        "kvm",
        "qemu",
    }:
        raise RuntimeError("QEMU guest required")
    out = Path("/opt/mano-lab/evidence")
    source_sockets = list(Path("/tmp/.X11-unix").glob("X*"))
    if len(source_sockets) != 1 or not source_sockets[0].is_socket():
        raise RuntimeError(f"Expected one task X11 server socket, got {source_sockets}")
    original = source_sockets[0]
    # Trigger wlroots' lazy internal XWayland before the auth file is generated.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as trigger:
        trigger.connect(str(original))
    display_file = Path("/run/mano-agent/x11-display")
    for _ in range(100):
        if display_file.exists() and Path("/run/mano-agent/Xauthority").exists():
            break
        time.sleep(0.1)
    display = display_file.read_text().strip()
    if display != ":" + original.name[1:]:
        raise RuntimeError("Display/socket identity mismatch")
    folder = Path("/run/mano-x11")
    folder.mkdir(mode=0o711, exist_ok=True)
    os.chown(folder, 0, 0)
    os.chmod(folder, 0o711)
    worker = pwd.getpwnam("mano-worker")
    allowed = folder / original.name
    if allowed.exists():
        raise RuntimeError("Refuse stale X11 endpoint")
    original.rename(allowed)
    os.chown(allowed, worker.pw_uid, worker.pw_gid)
    os.chmod(allowed, 0o600)
    auth = folder / "task-xauthority"
    shutil.copyfile("/run/mano-agent/Xauthority", auth)
    os.chown(auth, 0, worker.pw_gid)
    os.chmod(auth, 0o440)
    workspace = Path(tempfile.mkdtemp(prefix="x11-probe-", dir="/home/mano-worker"))
    os.chown(workspace, worker.pw_uid, worker.pw_gid)
    source = (
        "from pathlib import Path; import os,sys; from mano_lab.sandbox import command; "
        "a=command(Path(sys.argv[1]),sys.argv[4:],x11_socket=Path(sys.argv[2]),"
        "x11_authority=Path(sys.argv[3])); "
        'os.execve(a[0],a,{"PATH":"/usr/bin:/bin","LANG":"C.UTF-8"})'
    )

    def sandbox_args(argv):
        return [
            "/usr/sbin/runuser",
            "-u",
            "mano-worker",
            "--",
            "env",
            "-i",
            "PATH=/usr/bin:/bin",
            "PYTHONPATH=/opt/mano-lab/src",
            "python3",
            "-c",
            source,
            str(workspace),
            str(allowed),
            str(auth),
            *argv,
        ]

    observations = {
        "display": display,
        "socket_name": allowed.name,
        "auth_source": "generated task-only cookie",
    }
    positive = run(sandbox_args(["/usr/bin/xdpyinfo"]))
    if positive.returncode or "number of screens:" not in positive.stdout:
        raise RuntimeError(f"Authorized X11 query failed: {positive.stderr}")
    observations["authorized_x11_query"] = True
    # An outside principal cannot use the abstract listener, despite knowing its name.
    deny_abstract = run(
        [
            "/usr/sbin/runuser",
            "-u",
            "mano-worker",
            "--",
            "python3",
            "-c",
            "import socket,sys; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); "
            "s.settimeout(2); "
            'address="\\0/tmp/.X11-unix/"+sys.argv[1]; '
            '\ntry: s.connect(address)\nexcept OSError: print("abstract listener isolated")'
            '\nelse: raise AssertionError("abstract socket escaped namespace")',
            allowed.name,
        ]
    )
    if deny_abstract.returncode:
        raise RuntimeError(deny_abstract.stderr)
    xwayland_pids = [
        int(p) for p in run(["pgrep", "-u", "mano-agent", "-x", "Xwayland"]).stdout.split()
    ]
    if len(xwayland_pids) != 1:
        raise RuntimeError("Expected one actual internal XWayland process")
    xpid = xwayland_pids[0]
    caller_ns = os.readlink("/proc/self/ns/net")
    x11_ns = os.readlink(f"/proc/{xpid}/ns/net")
    if caller_ns == x11_ns:
        raise RuntimeError("XWayland network namespace was not isolated")
    inside = run(
        [
            "/usr/bin/nsenter",
            "-t",
            str(xpid),
            "-n",
            "python3",
            "-c",
            "import socket,sys; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); "
            "s.settimeout(2); s.connect('\\0/tmp/.X11-unix/'+sys.argv[1]); "
            "print('abstract positive control works inside namespace')",
            allowed.name,
        ]
    )
    if inside.returncode:
        raise RuntimeError(f"Abstract positive control failed: {inside.stderr}")
    observations["caller_net_namespace"] = caller_ns
    observations["xwayland_net_namespace"] = x11_ns
    observations["abstract_inside_positive_control"] = True
    observations["abstract_namespace_denied"] = True
    deny_role = run(
        [
            "/usr/sbin/runuser",
            "-u",
            "mano-core",
            "--",
            "python3",
            "-c",
            "import socket,sys; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); "
            '\ntry: s.connect(sys.argv[1])\nexcept PermissionError: print("other role denied")'
            '\nelse: raise AssertionError("other role reached task X11 socket")',
            str(allowed),
        ]
    )
    if deny_role.returncode:
        raise RuntimeError(deny_role.stderr)
    observations["other_principal_denied"] = True
    isolation = run(
        sandbox_args(
            [
                "/usr/bin/python3",
                "-c",
                "import os; from pathlib import Path; "
                'assert not Path("/run/mano-agent").exists(); '
                'assert not Path("/run/mano-human").exists(); '
                'assert not Path("/run/mano-worker").exists(); '
                'assert "WAYLAND_DISPLAY" not in os.environ; '
                'assert "SWAYSOCK" not in os.environ; print("raw Wayland and human IPC hidden")',
            ]
        )
    )
    if isolation.returncode:
        raise RuntimeError(isolation.stderr)
    observations["raw_wayland_human_ipc_hidden"] = True
    log = (out / "xmessage.txt").open("w")
    app = subprocess.Popen(
        sandbox_args(
            [
                "/usr/bin/xmessage",
                "-name",
                "mano-x11-probe",
                "-title",
                "mano-x11-probe",
                "-timeout",
                "20",
                "task-only X11",
            ]
        ),
        env=ENV,
        stdout=log,
        stderr=log,
    )
    try:
        mapped = False
        for _ in range(100):
            tree = run(
                [
                    "/usr/sbin/runuser",
                    "-u",
                    "mano-agent",
                    "--",
                    "env",
                    "-i",
                    "PATH=/usr/bin:/bin",
                    f"SWAYSOCK={sys.argv[1]}",
                    "swaymsg",
                    "-t",
                    "get_tree",
                    "-r",
                ]
            )

            def nodes(node):
                yield node
                for child in node.get("nodes", []) + node.get("floating_nodes", []):
                    yield from nodes(child)

            current = json.loads(tree.stdout)
            matched = [
                n for n in nodes(current) if n.get("name") == "mano-x11-probe" and n.get("window")
            ]
            if matched:
                mapped = True
                observations["mapped_x11_window"] = matched[0]
                break
            if app.poll() is not None:
                break
            time.sleep(0.1)
        if not mapped:
            raise RuntimeError("Authorized X11 window not observed by compositor")
        observations["compositor_network_namespace_isolated"] = True
        (out / "xwayland-confinement.json").write_text(json.dumps(observations, indent=2) + "\n")
        print(json.dumps(observations, indent=2))
        return 0
    finally:
        app.terminate()
        try:
            app.wait(timeout=5)
        except subprocess.TimeoutExpired:
            app.kill()
            app.wait()
        log.close()
        if allowed.is_socket():
            allowed.unlink()
        if auth.exists():
            auth.unlink()


if __name__ == "__main__":
    raise SystemExit(main())

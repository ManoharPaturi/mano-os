#!/usr/bin/env python3
"""Disposable guest experiment for actual Sway security-context enforcement."""

import json
import os
import pwd
import select
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from mano_lab.sandbox import ENV, require_patched

BINARY = "/usr/local/bin/mano-wayland-probe"
SOCKET = Path("/run/mano-worker/restricted-wayland")
PRIVILEGED = {
    "wp_security_context_manager_v1",
    "zwp_virtual_keyboard_manager_v1",
    "zwlr_virtual_pointer_manager_v1",
    "zwlr_screencopy_manager_v1",
    "zwlr_data_control_manager_v1",
    "zwlr_layer_shell_v1",
    "ext_session_lock_manager_v1",
    "zwp_input_method_manager_v2",
    "zwlr_output_manager_v1",
    "zwlr_output_power_manager_v1",
    "zwlr_gamma_control_manager_v1",
    "zwlr_export_dmabuf_manager_v1",
    "zwlr_foreign_toplevel_manager_v1",
    "ext_foreign_toplevel_list_v1",
    "zwp_keyboard_shortcuts_inhibit_manager_v1",
    "wp_transient_seat_manager_v1",
    "zxdg_output_manager_v1",
}


def run(argv):
    return subprocess.run(argv, env=ENV, text=True, capture_output=True, timeout=20, check=False)


def role(user, display, argv):
    return [
        "/usr/sbin/runuser",
        "-u",
        user,
        "--",
        "env",
        "-i",
        "PATH=/usr/bin:/bin",
        "LANG=C.UTF-8",
        "XDG_RUNTIME_DIR=/run/mano-agent",
        f"WAYLAND_DISPLAY={display}",
        *argv,
    ]


def inventory(text):
    result = {}
    for line in text.splitlines():
        ident, name, version = line.split()
        result[name] = (int(ident), int(version))
    return result


def main():
    require_patched()
    if os.getuid() != 0 or len(sys.argv) != 2:
        raise RuntimeError("Disposable guest supervisor and raw display required")
    marker = Path("/etc/mano-lab-disposable")
    if not marker.is_file() or marker.read_text().strip() != "mano-phase0-ci":
        raise RuntimeError("CI guest marker absent")
    if subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() not in {
        "kvm",
        "qemu",
    }:
        raise RuntimeError("Disposable QEMU guest required")
    agent = pwd.getpwnam("mano-agent")
    worker = pwd.getpwnam("mano-worker")
    out = Path("/opt/mano-lab/evidence")
    runtime = SOCKET.parent
    runtime.mkdir(exist_ok=True)
    if SOCKET.exists():
        raise RuntimeError("Refusing to reuse a prior listener")
    os.chown(runtime, agent.pw_uid, agent.pw_gid)
    os.chmod(runtime, 0o700)
    raw_display = sys.argv[1]
    raw = run(role("mano-agent", raw_display, [BINARY, "list"]))
    if raw.returncode:
        raise RuntimeError(raw.stderr)
    raw_globals = inventory(raw.stdout)
    required = {
        "wp_security_context_manager_v1",
        "zwp_virtual_keyboard_manager_v1",
        "zwlr_screencopy_manager_v1",
    }
    if not required <= raw_globals.keys():
        raise RuntimeError(f"Required privileged globals missing: {required - raw_globals.keys()}")
    listener = subprocess.Popen(
        role("mano-agent", raw_display, [BINARY, "listener", str(SOCKET)]),
        env=ENV,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    observations = {"raw_globals": raw_globals, "attacks": []}
    try:
        poll = select.poll()
        poll.register(listener.stdout, select.POLLIN | select.POLLHUP)
        if not poll.poll(10000) or listener.stdout.readline().strip() != "READY":
            raise RuntimeError("Restricted listener failed to become ready")
        os.chown(SOCKET, worker.pw_uid, worker.pw_gid)
        os.chmod(SOCKET, 0o600)
        # Worker can traverse to its socket but cannot replace the trusted endpoint.
        os.chown(runtime, 0, 0)
        os.chmod(runtime, 0o711)
        parent_write = run(
            [
                "/usr/sbin/runuser",
                "-u",
                "mano-worker",
                "--",
                "python3",
                "-c",
                "import os; assert not os.access('/run/mano-worker',os.W_OK); "
                "print('listener parent is not worker-writable')",
            ]
        )
        if parent_write.returncode:
            raise RuntimeError("Worker can replace its trusted endpoint")
        observations["listener_parent_write_denied"] = True
        # The worker cannot use the raw compositor path even outside its mount sandbox.
        attack_raw = run(role("mano-worker", raw_display, [BINARY, "surface"]))
        observations["raw_socket_worker_exit"] = attack_raw.returncode
        if attack_raw.returncode != 2 or "display connect" not in attack_raw.stderr:
            raise RuntimeError("Worker unexpectedly accessed raw display")
        workspace = Path(tempfile.mkdtemp(prefix="gui-probe-", dir="/home/mano-worker"))
        os.chown(workspace, worker.pw_uid, worker.pw_gid)

        def sandbox_args(argv):
            # Construct as the worker so the ownership guard observes real credentials.
            source = (
                "from pathlib import Path; import os; from mano_lab.sandbox import command; "
                "import sys; a=command(Path(sys.argv[1]),sys.argv[2:],"
                'Path("/run/mano-worker/restricted-wayland")); '
                'os.execve(a[0],a,{"PATH":"/usr/bin:/bin","LANG":"C.UTF-8"})'
            )
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
                *argv,
            ]

        def sandbox(argv):
            return run(sandbox_args(argv))

        restricted = sandbox([BINARY, "list"])
        if restricted.returncode:
            raise RuntimeError(restricted.stderr)
        restricted_globals = inventory(restricted.stdout)
        observations["restricted_globals"] = restricted_globals
        leaked = PRIVILEGED & restricted_globals.keys()
        if leaked:
            raise RuntimeError(f"Privileged globals leaked into worker: {leaked}")
        positive = sandbox([BINARY, "surface"])
        if positive.returncode or "ordinary surface works" not in positive.stdout:
            raise RuntimeError(
                f"Ordinary sandboxed client cannot create surface: {positive.stderr}"
            )
        observations["ordinary_surface"] = positive.stdout.strip()
        for name in sorted(PRIVILEGED & raw_globals.keys()):
            ident, version = raw_globals[name]
            denied = sandbox([BINARY, "bind", str(ident), name, str(version)])
            observations["attacks"].append(
                {
                    "interface": name,
                    "raw_global_id": ident,
                    "exit": denied.returncode,
                    "stdout": denied.stdout,
                    "stderr": denied.stderr,
                }
            )
            if denied.returncode != 3 or "server denied bind" not in denied.stdout:
                raise RuntimeError(f"Forged global bind not rejected: {name}: {denied.stderr}")
        # Positive authority control: trusted raw client can bind a harmless manager.
        ident, version = raw_globals["zwp_virtual_keyboard_manager_v1"]
        trusted = run(
            role(
                "mano-agent",
                raw_display,
                [BINARY, "bind", str(ident), "zwp_virtual_keyboard_manager_v1", str(version)],
            )
        )
        if trusted.returncode or "bind succeeded" not in trusted.stdout:
            raise RuntimeError("Trusted controller positive bind failed")
        observations["trusted_bind_control"] = trusted.stdout.strip()
        # Socket namespace exposes neither Sway command IPC nor raw X11/human input.
        isolation = sandbox(
            [
                "/usr/bin/python3",
                "-c",
                "import os; from pathlib import Path; "
                'assert not Path("/run/mano-agent").exists(); '
                'assert not Path("/run/mano-human").exists(); '
                'assert not Path("/tmp/.X11-unix").exists(); '
                'assert "DISPLAY" not in os.environ; '
                'assert "SWAYSOCK" not in os.environ; print("raw IPC and X11 hidden")',
            ]
        )
        if isolation.returncode:
            raise RuntimeError(isolation.stderr)
        observations["ipc_isolation"] = isolation.stdout.strip()
        observations["xwayland_client_contract"] = "pending; no X11 socket granted to this worker"
        # Preserve the independent confinement outcome even if a later app contract fails.
        (out / "wayland-confinement.json").write_text(json.dumps(observations, indent=2) + "\n")
        # Headed system Chromium remains open until a trusted observer confirms its window.
        shutil.copyfile(
            "/opt/mano-lab/tests/desktop/browser_contract.py", workspace / "browser_contract.py"
        )
        browser_log = (out / "browser-worker.txt").open("w")
        browser_worker = subprocess.Popen(
            sandbox_args(
                [
                    "/usr/local/lib/mano-browser/bin/python",
                    "/workspace/browser_contract.py",
                ]
            ),
            env=ENV,
            stdout=browser_log,
            stderr=browser_log,
        )
        try:
            deadline = time.monotonic() + 50
            while not (workspace / "browser-ready.json").is_file():
                if browser_worker.poll() is not None:
                    raise RuntimeError("Browser worker exited before verified page readiness")
                if time.monotonic() > deadline:
                    raise RuntimeError("Browser readiness timed out")
                time.sleep(0.1)
            observed = False
            for _ in range(50):
                trees = run(
                    role(
                        "mano-agent",
                        raw_display,
                        [
                            "env",
                            "SWAYSOCK="
                            + str(next(Path("/run/mano-agent").glob("sway-ipc.*.sock"))),
                            "swaymsg",
                            "-t",
                            "get_tree",
                            "-r",
                        ],
                    )
                )

                def nodes(node):
                    yield node
                    for child in node.get("nodes", []) + node.get("floating_nodes", []):
                        yield from nodes(child)

                matches = [
                    node
                    for node in nodes(json.loads(trees.stdout))
                    if (node.get("name") or "").startswith("mano-browser-contract")
                    and "chromium" in (node.get("app_id") or "").lower()
                ]
                if matches:
                    observed = True
                    (out / "browser-window.json").write_text(
                        json.dumps(matches[0], indent=2) + "\n"
                    )
                    break
                time.sleep(0.1)
            if not observed:
                raise RuntimeError("Headed Chromium window not observed by compositor")
            (workspace / "observer-done").touch()
            if browser_worker.wait(timeout=20) != 0:
                raise RuntimeError("Browser contract failed after observation")
            for name in ("browser-contract.json", "browser-page.png", "browser-trace.zip"):
                shutil.copyfile(workspace / name, out / name)
            observations["system_browser_contract"] = (
                "passed with independent mapped-window observation"
            )
        finally:
            if browser_worker.poll() is None:
                browser_worker.terminate()
                try:
                    browser_worker.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    browser_worker.kill()
                    browser_worker.wait()
            browser_log.close()
        (out / "wayland-confinement.json").write_text(json.dumps(observations, indent=2) + "\n")
        print(json.dumps(observations, indent=2))
        return 0
    finally:
        listener.terminate()
        try:
            listener.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            listener.kill()
            listener.communicate()
        # Current experiment's socket only; older workspaces/artifacts are retained.
        if SOCKET.is_socket():
            SOCKET.unlink()


if __name__ == "__main__":
    raise SystemExit(main())

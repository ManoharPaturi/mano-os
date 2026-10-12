#!/usr/bin/env python3
"""Actual Debian guest probes. Failed tests fail CI; pending physical gates do not.

The source is a lab tool, not a production approval service. No LLM is connected.
"""

import json
import os
import pwd
import subprocess
import sys
import time
from pathlib import Path

from mano_lab.evidence import Probe, write_report

ROOT = Path("/opt/mano-lab")
OUT = ROOT / "evidence"
PROBES = []


def call(argv, timeout=60):
    return subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)


def record(issue, name, result, expected=0):
    log = name + ".txt"
    (OUT / log).write_text(
        json.dumps(
            {"exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr},
            indent=2,
        )
    )
    status = "pass" if result.returncode == expected else "fail"
    PROBES.append(
        Probe(issue, name, status, f"Expected exit {expected}, got {result.returncode}", (log,))
    )
    return status == "pass"


def agent(argv):
    return [
        "runuser",
        "-u",
        "mano-agent",
        "--",
        "env",
        "-i",
        "PATH=/usr/bin:/bin",
        "HOME=/home/mano-agent",
        "LANG=C.UTF-8",
        "PYTHONPATH=/opt/mano-lab/src",
        *argv,
    ]


def sandbox_probes():
    workspace = Path("/home/mano-agent/workspace")
    workspace.mkdir()
    account = pwd.getpwnam("mano-agent")
    os.chown(workspace, account.pw_uid, account.pw_gid)
    # One sandbox contains malicious attempts after proving it actually executes.
    source = (ROOT / "scripts/sandbox_negative.py").read_text()
    result = call(agent(["python3", "-c", source]))
    record("P0-08", "sandbox-kernel-denials", result)
    record(
        "P0-02",
        "protected-sentinels",
        call(
            [
                "python3",
                "-c",
                "from pathlib import Path; assert Path('/etc/mano/sentinel').read_text()=="
                "'protected-policy\\n'; assert Path('/var/lib/mano-broker/sentinel').read_text()=="
                "'protected-journal\\n'; print('unchanged')",
            ]
        ),
    )
    record(
        "P0-09",
        "agent-human-runtime-permission-denial",
        call(
            agent(
                [
                    "python3",
                    "-c",
                    "import os; assert not os.access('/run/mano-human',os.R_OK); "
                    "print('Human runtime inaccessible to agent principal')",
                ]
            )
        ),
    )
    PROBES.append(
        Probe(
            "P0-09",
            "physical-approval-provenance",
            "pending",
            "Real physical input, full approval service and uinput attack require hardware",
        )
    )


def desktop_probe():
    log = (OUT / "sway.txt").open("w")
    compositor = subprocess.Popen(
        agent(
            [
                "XDG_RUNTIME_DIR=/run/mano-agent",
                "WLR_BACKENDS=headless",
                "WLR_RENDERER=pixman",
                "WLR_HEADLESS_OUTPUTS=1",
                "sway",
                "-c",
                str(ROOT / "packaging/sway/agent.conf"),
            ]
        ),
        stdout=log,
        stderr=log,
    )
    try:
        socket_path = None
        for _ in range(100):
            matches = list(Path("/run/mano-agent").glob("sway-ipc.*.sock"))
            if matches:
                socket_path = str(matches[0])
                break
            if compositor.poll() is not None:
                break
            time.sleep(0.1)
        if socket_path is None:
            PROBES.append(Probe("P0-04", "headless-sway", "fail", "No IPC socket", ("sway.txt",)))
            return
        env = [
            "XDG_RUNTIME_DIR=/run/mano-agent",
            f"SWAYSOCK={socket_path}",
            "WAYLAND_DISPLAY=wayland-1",
        ]
        result = call(agent([*env, "swaymsg", "-t", "get_outputs", "-r"]))
        try:
            outputs = json.loads(result.stdout)
            if not any(o.get("active") and o.get("name") == "HEADLESS-1" for o in outputs):
                raise ValueError("No active headless output")
        except (ValueError, TypeError):
            result = subprocess.CompletedProcess([], 1, result.stdout, result.stderr)
        record("P0-04", "headless-sway-output", result)
        # Diagnostic renderer checks are not sandboxed GUI-worker release proof.
        record(
            "P0-05",
            "diagnostic-foot-launch",
            call(
                agent(
                    [
                        *env,
                        "swaymsg",
                        "exec",
                        "foot --title mano-phase0 /bin/sleep 30",
                    ]
                )
            ),
        )
        time.sleep(2)
        tree = call(agent([*env, "swaymsg", "-t", "get_tree", "-r"]))
        try:

            def nodes(node):
                yield node
                for child in node.get("nodes", []) + node.get("floating_nodes", []):
                    yield from nodes(child)

            observed = any(n.get("name") == "mano-phase0" for n in nodes(json.loads(tree.stdout)))
            if not observed:
                tree = subprocess.CompletedProcess([], 1, tree.stdout, "Expected window not mapped")
        except (ValueError, TypeError):
            tree = subprocess.CompletedProcess([], 1, tree.stdout, "Invalid Sway tree")
        record("P0-05", "diagnostic-foot-observed", tree)
        record(
            "P0-04",
            "headless-screenshot",
            call(
                agent(
                    [
                        *env,
                        "grim",
                        "/home/mano-agent/desktop.png",
                    ]
                )
            ),
        )
        image = Path("/home/mano-agent/desktop.png")
        if image.exists():
            (OUT / "desktop.png").write_bytes(image.read_bytes())
        record(
            "P0-07",
            "wayland-global-inventory",
            call(
                agent(
                    [
                        *env,
                        "wayland-info",
                    ]
                )
            ),
        )
        PROBES.append(
            Probe(
                "P0-07",
                "privileged-protocol-denial",
                "pending",
                "Inventory is not proof that malicious clients cannot bind privileged globals",
            )
        )
        PROBES.append(
            Probe(
                "P0-05",
                "chromium-libreoffice-isolated-input",
                "pending",
                "Controlled GUI input, cross-session focus, and sandboxed app contracts pending",
            )
        )
        PROBES.append(
            Probe(
                "P0-06",
                "atspi-coordinate-action",
                "pending",
                "Accessibility tree plus named action/scale mapping not yet validated",
            )
        )
    finally:
        if compositor.poll() is None:
            call(["pkill", "-u", "mano-agent", "-x", "sway"])
        compositor.wait(timeout=10)
        log.close()


def stop_probe():
    # Trusted systemd remains functional while a mock core process is SIGSTOPed.
    result = call(
        [
            "systemd-run",
            "--unit=mano-lab-task",
            "--slice=mano-lab-tasks.slice",
            "-p",
            "MemoryMax=64M",
            "-p",
            "TasksMax=16",
            "-p",
            "CPUQuota=20%",
            "-p",
            "User=mano-agent",
            "/bin/sh",
            "-c",
            "sleep infinity & wait",
        ]
    )
    if not record("P0-10", "cgroup-task-start", result):
        return
    started = call(
        [
            "systemd-run",
            "--unit=mano-lab-core",
            "-p",
            "User=mano-core",
            "-p",
            "MemoryMax=64M",
            "/bin/sleep",
            "infinity",
        ]
    )
    if not record("P0-10", "mock-core-service-start", started):
        call(["systemctl", "stop", "mano-lab-tasks.slice"])
        return
    pid_result = call(["systemctl", "show", "mano-lab-core.service", "-p", "MainPID", "--value"])
    core_pid = int(pid_result.stdout.strip())
    if core_pid <= 0:
        raise RuntimeError("No actual mock-core service process")
    task_group = call(
        [
            "systemctl",
            "show",
            "mano-lab-task.service",
            "-p",
            "ControlGroup",
            "--value",
        ]
    ).stdout.strip()
    slice_group = call(
        [
            "systemctl",
            "show",
            "mano-lab-tasks.slice",
            "-p",
            "ControlGroup",
            "--value",
        ]
    ).stdout.strip()
    if (
        not slice_group
        or slice_group == "/"
        or task_group == slice_group
        or not Path(task_group).is_relative_to(Path(slice_group))
    ):
        call(["systemctl", "stop", "mano-lab-core.service", "mano-lab-tasks.slice"])
        raise RuntimeError("Task not placed beneath the broker-selected task slice")
    (OUT / "stop-cgroup-layout.txt").write_text(
        json.dumps(
            {
                "task_cgroup": task_group,
                "slice_cgroup": slice_group,
                "core_main_pid": core_pid,
            },
            indent=2,
        )
    )
    try:
        os.kill(core_pid, 19)  # SIGSTOP the actual service process, not a wrapper.
        time.sleep(0.1)
        state = Path(f"/proc/{core_pid}/status").read_text()
        frozen = any(
            line.startswith("State:") and "T (stopped)" in line for line in state.splitlines()
        )
        record(
            "P0-10",
            "mock-core-actually-frozen",
            subprocess.CompletedProcess(
                [],
                0 if frozen else 1,
                state,
                "",
            ),
        )
        record(
            "P0-10",
            "independent-systemd-stop",
            call(
                [
                    "systemctl",
                    "stop",
                    "mano-lab-tasks.slice",
                ]
            ),
        )
        group = Path("/sys/fs/cgroup") / task_group.lstrip("/")
        remaining = []
        if group.exists():
            for procs in group.rglob("cgroup.procs"):
                remaining.extend(procs.read_text().split())
        record(
            "P0-10",
            "task-descendants-terminated",
            subprocess.CompletedProcess(
                [],
                1 if remaining else 0,
                f"Remaining cgroup PIDs: {remaining}",
                "",
            ),
        )
        record(
            "P0-10",
            "task-terminated",
            call(
                [
                    "python3",
                    "-c",
                    "import subprocess; p=subprocess.run(['systemctl','is-active',"
                    "'mano-lab-task.service'],capture_output=True,text=True); "
                    "assert p.stdout.strip() in {'inactive','failed','unknown'},p.stdout; "
                    "print(p.stdout)",
                ]
            ),
        )
    finally:
        call(["systemctl", "kill", "--signal=SIGKILL", "mano-lab-core.service"])
        call(["systemctl", "stop", "mano-lab-core.service", "mano-lab-tasks.slice"])
    PROBES.append(
        Probe(
            "P0-10",
            "trusted-physical-stop-path",
            "pending",
            "Systemd primitive tested; physical/TTY stopd and grant revocation still pending",
        )
    )


def oom_probe():
    observer = call(
        [
            "systemd-run",
            "--unit=mano-lab-human-observer",
            "-p",
            "User=mano-human",
            "/bin/sleep",
            "infinity",
        ]
    )
    if not record("P0-12", "oom-observer-start", observer):
        return
    try:
        result = call(
            [
                "systemd-run",
                "--unit=mano-lab-oom",
                "--wait",
                "--pipe",
                "-p",
                "MemoryMax=32M",
                "-p",
                "MemorySwapMax=0",
                "-p",
                "TasksMax=8",
                "-p",
                "OOMPolicy=kill",
                "-p",
                "User=mano-agent",
                "/usr/bin/python3",
                "-c",
                "a=bytearray(128*1024*1024)",
            ],
            timeout=30,
        )
        (OUT / "oom-allocation.txt").write_text(
            f"exit={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}"
        )
        verify = call(
            [
                "python3",
                "-c",
                "import subprocess; p=subprocess.run(['systemctl','show','mano-lab-oom.service',"
                "'-p','Result','--value'],capture_output=True,text=True); "
                "assert p.stdout.strip()=='oom-kill',p.stdout; print(p.stdout); "
                "q=subprocess.run(['systemctl','is-active','mano-lab-human-observer.service'],"
                "capture_output=True,text=True); assert q.stdout.strip()=='active',q.stdout; "
                "print('Human observer survived task OOM')",
            ]
        )
        record("P0-12", "cgroup-oom-contained", verify)
    finally:
        call(["systemctl", "stop", "mano-lab-human-observer.service"])


def main():
    if os.getuid() != 0 or not Path("/dev/vdb").exists():
        raise RuntimeError("Run only in the disposable VM through guest_lab.sh")
    PROBES.extend(
        [
            Probe(
                "P0-01",
                "debian-vm-4g",
                "pass",
                "QEMU Debian 13 guest under an 8 GB ceiling",
                ("kernel.txt", "memory-before.txt"),
            ),
            Probe(
                "P0-01", "btrfs-root-install", "pending", "Cloud root is ext4; secondary btrfs only"
            ),
            Probe(
                "P0-02",
                "patched-packages",
                "pass",
                "Guest enforces bubblewrap and D-Bus proxy floors",
                ("packages.tsv",),
            ),
            Probe(
                "P0-03",
                "physical-prompt-rescue",
                "pending",
                "Native prompt and physical recovery TTY pending",
            ),
            Probe(
                "P0-11",
                "snapper-data-restore",
                "pass",
                "Exact sentinel restored on btrfs data subvolume",
                ("snapper.txt", "mounts.json"),
            ),
            Probe("P0-11", "root-rollback-rescue", "pending", "Root/boot restoration not proven"),
            Probe(
                "P0-12",
                "physical-8gb-performance",
                "pending",
                "VM memory is not physical laptop performance",
            ),
        ]
    )
    try:
        sandbox_probes()
        desktop_probe()
        stop_probe()
        oom_probe()
    except Exception as exc:
        (OUT / "exception.txt").write_text(repr(exc))
        PROBES.append(Probe("P0-12", "probe-harness", "fail", str(exc), ("exception.txt",)))
    report = write_report(
        OUT,
        PROBES,
        {
            "kind": "disposable-debian13-qemu",
            "ram_ceiling_mib": 4096,
            "physical_hardware": False,
            "agent_connected": False,
        },
    )
    print(json.dumps(report, indent=2))
    return 1 if any(p.status == "fail" for p in PROBES) else 0


if __name__ == "__main__":
    sys.exit(main())

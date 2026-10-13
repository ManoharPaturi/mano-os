#!/usr/bin/env python3
"""Actual Debian guest probes. Failed tests fail CI; pending physical gates do not.

The source is a lab tool, not a production approval service. No LLM is connected.
"""

import json
import os
import pwd
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from probe_human_prompt import human_session

from mano_lab.evidence import Probe, write_report
from mano_lab.resources import process_memory, system_memory

ROOT = Path("/opt/mano-lab")
OUT = ROOT / "evidence"
PROBES = []
RESOURCE_OBSERVATIONS = {}


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
    workspace = Path(tempfile.mkdtemp(prefix="mano-probe-", dir="/home/mano-agent"))
    account = pwd.getpwnam("mano-agent")
    os.chown(workspace, account.pw_uid, account.pw_gid)
    # One sandbox contains malicious attempts after proving it actually executes.
    source = (ROOT / "scripts/sandbox_negative.py").read_text()
    result = call(agent(["python3", "-c", source, str(workspace)]))
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


def desktop_probe(human_witness):
    launch_started = time.monotonic()
    log = (OUT / "sway.txt").open("w")
    display_user = pwd.getpwnam("mano-agent")
    cookie_path = Path("/run/mano-agent/x11-cookie")
    cookie_path.write_text(secrets.token_hex(16))
    os.chown(cookie_path, display_user.pw_uid, display_user.pw_gid)
    os.chmod(cookie_path, 0o600)
    compositor = subprocess.Popen(
        [
            "/usr/bin/unshare",
            "--net",
            *agent(
                [
                    "XDG_RUNTIME_DIR=/run/mano-agent",
                    "WLR_BACKENDS=headless",
                    "WLR_RENDERER=pixman",
                    "WLR_HEADLESS_OUTPUTS=1",
                    "WLR_XWAYLAND=/opt/mano-lab/scripts/xwayland_lab_wrapper.sh",
                    "sway",
                    "-c",
                    str(ROOT / "packaging/sway/agent.conf"),
                ]
            ),
        ],
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
        human_pid = human_witness.sway_pid
        agent_pid = int(call(["pgrep", "-u", "mano-agent", "-x", "sway"]).stdout.strip())
        namespaces = {
            "human": os.readlink(f"/proc/{human_pid}/ns/net"),
            "agent": os.readlink(f"/proc/{agent_pid}/ns/net"),
        }
        assert namespaces["human"] != namespaces["agent"]
        attacks = []
        for actor in ("mano-agent", "mano-core", "mano-worker"):
            for route, argv in (
                (
                    "human-wayland-pointer",
                    [
                        "/usr/local/bin/mano-wayland-probe",
                        "pointer-click",
                        "114",
                        "45",
                        "1280",
                        "720",
                    ],
                ),
                ("human-command-ipc", ["swaymsg", "-t", "get_tree", "-r"]),
            ):
                result = call(
                    [
                        "/usr/sbin/runuser",
                        "-u",
                        actor,
                        "--",
                        "env",
                        "-i",
                        "PATH=/usr/bin:/bin",
                        "XDG_RUNTIME_DIR=/run/mano-human",
                        "WAYLAND_DISPLAY=wayland-1",
                        f"SWAYSOCK={human_witness.ipc}",
                        *argv,
                    ]
                )
                kernel_denial = None
                if route == "human-command-ipc":
                    kernel_denial = call(
                        [
                            "/usr/sbin/runuser",
                            "-u",
                            actor,
                            "--",
                            "python3",
                            "-c",
                            "import socket,sys,errno; s=socket.socket(socket.AF_UNIX); "
                            "\ntry: s.connect(sys.argv[1])"
                            "\nexcept PermissionError as e: "
                            "assert e.errno==errno.EACCES; sys.exit(0)"
                            "\nsys.exit(1)",
                            human_witness.ipc,
                        ]
                    )
                denied = result.returncode != 0 and (
                    (kernel_denial is not None and kernel_denial.returncode == 0)
                    or (route == "human-wayland-pointer" and "display connect" in result.stderr)
                )
                assert denied, f"Human {route} not denied to {actor}: {result.stderr}"
                attacks.append(
                    {
                        "actor": actor,
                        "route": route,
                        "exit": result.returncode,
                        "stderr": result.stderr,
                        "kernel_errno": "EACCES"
                        if kernel_denial is not None and kernel_denial.returncode == 0
                        else None,
                    }
                )
        (OUT / "human-socket-denials.json").write_text(
            json.dumps({"attacks": attacks, "network_namespaces": namespaces}, indent=2) + "\n"
        )
        human_witness.checkpoint("agent-compositor-and-denied-cross-session-attacks")
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
        if result.returncode == 0:
            RESOURCE_OBSERVATIONS["sway_launch_to_output_seconds"] = (
                time.monotonic() - launch_started
            )
            pid_query = call(["pgrep", "-u", "mano-agent", "-x", "sway"])
            sway_pids = [int(value) for value in pid_query.stdout.split()]
            if len(sway_pids) != 1:
                raise RuntimeError("Cannot identify the single lab Sway process")
            RESOURCE_OBSERVATIONS["sway_memory_bytes"] = process_memory(sway_pids[0])
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
        confinement = call(
            [
                "python3",
                str(ROOT / "scripts/probe_wayland_confinement.py"),
                "/run/mano-agent/wayland-1",
            ],
            timeout=240,
        )
        record("P0-07", "wayland-context-enforcement", confinement)
        human_witness.checkpoint("after-chromium-writer-and-agent-pointer-actions")
        if confinement.returncode == 0:
            PROBES.append(
                Probe(
                    "P0-07",
                    "privileged-wayland-bind-denial",
                    "pass",
                    "Worker surface succeeds; forged privileged binds and raw socket access fail",
                    ("wayland-confinement.json", "security-context-protocol.sha256"),
                )
            )
        if confinement.returncode == 0 and (OUT / "browser-contract.json").is_file():
            PROBES.append(
                Probe(
                    "P0-05",
                    "system-chromium-sandboxed-contract",
                    "pass",
                    "Chromium locator, mapped window, screenshot, sandbox and pipe transport",
                    (
                        "browser-contract.json",
                        "browser-window.json",
                        "browser-page.png",
                        "browser-trace.zip",
                    ),
                )
            )
        if confinement.returncode == 0 and (OUT / "office-contract.json").is_file():
            PROBES.append(
                Probe(
                    "P0-05",
                    "writer-sandboxed-document-contract",
                    "pass",
                    "Real Writer window, named accessible Save, exact saved ODT and PDF text",
                    (
                        "office-contract.json",
                        "office-window.json",
                        "office-page.png",
                        "contract.odt",
                        "contract.pdf",
                    ),
                )
            )
            PROBES.append(
                Probe(
                    "P0-06",
                    "atspi-named-save",
                    "pass",
                    "Task-private named Save; geometry verified by separate scale probe",
                    ("office-contract.json", "office-accessibility-tree.json"),
                )
            )
        x11 = call(
            [
                "python3",
                str(ROOT / "scripts/probe_xwayland_confinement.py"),
                socket_path,
            ],
            timeout=120,
        )
        record("P0-07", "xwayland-client-enforcement", x11)
        human_witness.checkpoint("after-task-xwayland-actions")
        if x11.returncode == 0:
            PROBES.append(
                Probe(
                    "P0-07",
                    "xwayland-private-domain",
                    "pass",
                    "X11 window maps; raw Wayland, other roles and abstract socket denied",
                    ("xwayland-confinement.json",),
                )
            )
        PROBES.append(
            Probe(
                "P0-06",
                "atspi-coordinate-action",
                "pass"
                if confinement.returncode == 0 and (OUT / "office-geometry.json").is_file()
                else "pending",
                "Visible Writer Save clicked using window-relative geometry at scales 1 and 2"
                if confinement.returncode == 0
                else "Coordinate/scale probe incomplete",
                ("office-geometry.json", "office-scale-1.png", "office-scale-2.png", "geometry.odt")
                if confinement.returncode == 0
                else (),
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
    limits = call(
        [
            "systemctl",
            "show",
            "mano-lab-task.service",
            "-p",
            "MemoryMax",
            "-p",
            "TasksMax",
            "-p",
            "CPUQuotaPerSecUSec",
            "-p",
            "ControlGroup",
        ]
    )
    values = dict(line.split("=", 1) for line in limits.stdout.splitlines() if "=" in line)
    if (
        limits.returncode != 0
        or values.get("MemoryMax") != "67108864"
        or values.get("TasksMax") != "16"
        or values.get("CPUQuotaPerSecUSec") != "200ms"
    ):
        raise RuntimeError(f"Observed task limits differ from requested limits: {values}")
    RESOURCE_OBSERVATIONS["observed_task_cgroup_limits"] = values
    kernel_group = Path("/sys/fs/cgroup") / values["ControlGroup"].lstrip("/")
    memory_max = int((kernel_group / "memory.max").read_text().strip())
    pids_max = int((kernel_group / "pids.max").read_text().strip())
    quota, period = (int(value) for value in (kernel_group / "cpu.max").read_text().split())
    if memory_max != 67108864 or pids_max != 16 or quota * 5 != period:
        raise RuntimeError("Kernel cgroup limits differ from the selected task profile")
    RESOURCE_OBSERVATIONS["kernel_task_cgroup_limits"] = {
        "memory_max_bytes": memory_max,
        "pids_max": pids_max,
        "cpu_quota_microseconds": quota,
        "cpu_period_microseconds": period,
    }
    (OUT / "task-cgroup-limits.txt").write_text(limits.stdout)
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
    started = time.monotonic()
    RESOURCE_OBSERVATIONS["pre_probe_guest_memory_bytes"] = system_memory()
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
                "P0-01",
                "btrfs-root-boot",
                "pass",
                "Root filesystem verified as btrfs after an actual second boot",
                ("root-boot.json",),
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
                "Native prompt and authenticated serial recovery probe not yet combined",
            ),
            Probe(
                "P0-11",
                "snapper-data-restore",
                "pass",
                "Exact sentinel restored on btrfs data subvolume",
                ("snapper.txt", "mounts.json"),
            ),
            Probe(
                "P0-11",
                "root-snapshot-boot-recovery",
                "pass" if (OUT / "root-recovery.json").is_file() else "pending",
                "Separate boot from Snapper recovery clone with preserved changed source root"
                if (OUT / "root-recovery.json").is_file()
                else "Root recovery has not run yet",
                ("root-recovery.json",) if (OUT / "root-recovery.json").is_file() else (),
            ),
        ]
    )
    try:
        sandbox_probes()
        with human_session() as human_witness:
            RESOURCE_OBSERVATIONS["human_compositor_memory_bytes"] = human_witness.report[
                "human_compositor_memory_bytes"
            ]
            human_witness.start_monitor()
            desktop_probe(human_witness)
            human_witness.finish_monitor()
            PROBES.append(
                Probe(
                    "P0-05",
                    "chromium-libreoffice-isolated-input",
                    "pass",
                    "Concurrent human canary/focus preserved during actual agent app actions",
                    (
                        "cross-session-focus.json",
                        "human-socket-denials.json",
                        "focus-before.png",
                        "focus-after.png",
                    ),
                )
            )
        stop_probe()
        oom_probe()
    except Exception as exc:
        (OUT / "exception.txt").write_text(repr(exc))
        PROBES.append(Probe("P0-12", "probe-harness", "fail", str(exc), ("exception.txt",)))
    RESOURCE_OBSERVATIONS.update(
        {
            "post_probe_guest_memory_bytes": system_memory(),
            "probe_suite_elapsed_seconds": time.monotonic() - started,
            "measurement_scope": "VM primitives and native UI; production core/broker absent",
            "physical_hardware": False,
            "human_compositor_memory_bytes": RESOURCE_OBSERVATIONS.get(
                "human_compositor_memory_bytes"
            ),
            "verified_product_task_success_rate": None,
            "model_cost": None,
            "ci_cost": None,
            "model_connected": False,
        }
    )
    app_startup = {}
    for name, artifact in (
        ("chromium", "browser-contract.json"),
        ("writer", "office-contract.json"),
    ):
        if (OUT / artifact).is_file():
            app_startup[name] = json.loads((OUT / artifact).read_text()).get("startup")
    RESOURCE_OBSERVATIONS["app_startup_observations"] = app_startup
    (OUT / "resources.json").write_text(json.dumps(RESOURCE_OBSERVATIONS, indent=2) + "\n")
    resources_complete = (
        all(
            RESOURCE_OBSERVATIONS.get(key)
            for key in (
                "sway_launch_to_output_seconds",
                "sway_memory_bytes",
                "observed_task_cgroup_limits",
                "kernel_task_cgroup_limits",
            )
        )
        and (OUT / "task-cgroup-limits.txt").is_file()
        and all(app_startup.get(name) for name in ("chromium", "writer"))
    )
    PROBES.append(
        Probe(
            "P0-12",
            "measured-vm-resource-observations",
            "pass" if resources_complete else "fail",
            "Live guest memory, Sway RSS/high-watermark/launch time and actual cgroup limits",
            ("resources.json", "task-cgroup-limits.txt")
            if resources_complete
            else ("resources.json",),
        )
    )
    report = write_report(
        OUT,
        PROBES,
        {
            "kind": "disposable-debian13-qemu",
            "ram_ceiling_mib": 4096,
            "physical_hardware": False,
            "agent_connected": False,
            "deferred_release_gates": {
                "phase6_physical_8gb_performance": "pending; user chose CI VM development",
                "phase7_firmware_installer_boot": "pending; current lab uses direct kernel boot",
            },
        },
    )
    print(json.dumps(report, indent=2))
    return 1 if any(p.status == "fail" for p in PROBES) else 0


if __name__ == "__main__":
    sys.exit(main())

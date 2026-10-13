#!/usr/bin/env python3
"""Root-only disposable setup/observations; native stopd is independently tested."""

import json
import os
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

BASE = Path("/run/mano-stop-fixture")
OUT = Path("/opt/mano-lab/evidence")
DISPLAY = Path("/run/mano-stop-agent")
SLICE = "mano-stop-tasks.slice"


def run(argv, check=True):
    print(json.dumps({"command": argv}), file=sys.stderr, flush=True)
    return subprocess.run(argv, text=True, capture_output=True, timeout=20, check=check)


def prop(unit, name):
    return run(["systemctl", "show", unit, "-p", name, "--value"]).stdout.strip()


def frozen(unit):
    pid = int(prop(unit, "MainPID"))
    state = Path(f"/proc/{pid}/status").read_text()
    assert "T (stopped)" in state
    return {"pid": pid, "state": "T (stopped)"}


def query_seat():
    sock = next(DISPLAY.glob("sway-ipc.*.sock"))
    seats = json.loads(run(["env", f"SWAYSOCK={sock}", "swaymsg", "-t", "get_seats", "-r"]).stdout)
    return seats


def phase_start(phase):
    grant = json.loads(Path("/var/lib/mano-broker/live-grant.json").read_text())
    assert grant["epoch"] == int(Path("/var/lib/mano-broker/grant-epoch").read_text())
    assert not Path("/var/lib/mano-broker/stop-latched").exists()
    for index in (1, 2):
        run(
            [
                "systemd-run",
                f"--unit=mano-stop-{phase}-{index}",
                f"--slice={SLICE}",
                "--property=Type=exec",
                "--uid=mano-worker",
                "--property=TasksMax=24",
                "--property=MemoryMax=48M",
                "--property=CPUQuota=20%",
                "/usr/bin/python3",
                "/opt/mano-lab/tests/desktop/fork_storm.py",
            ]
        )
    run(
        [
            "systemd-run",
            f"--unit=mano-stop-{phase}-input",
            f"--slice={SLICE}",
            "--property=Type=exec",
            "--uid=mano-agent",
            "--property=TasksMax=8",
            f"--property=StandardOutput=append:{BASE}/pulse-{phase}.log",
            "--setenv=XDG_RUNTIME_DIR=/run/mano-stop-agent",
            "--setenv=WAYLAND_DISPLAY=wayland-1",
            "/usr/local/bin/mano-wayland-probe",
            "pointer-pulse",
        ]
    )
    group = Path("/sys/fs/cgroup") / prop(SLICE, "ControlGroup").lstrip("/")
    deadline = time.monotonic() + 10
    while True:
        pids = [
            int(value) for file in group.rglob("cgroup.procs") for value in file.read_text().split()
        ]
        pulse = BASE / f"pulse-{phase}.log"
        limits = {
            file.parent.name: file.read_text().strip()
            for file in group.rglob("pids.events")
            if file.parent.name.endswith(f"{phase}-1.service")
            or file.parent.name.endswith(f"{phase}-2.service")
        }
        saturated = len(limits) == 2 and all(
            any(line.startswith("max ") and int(line.split()[1]) > 0 for line in value.splitlines())
            for value in limits.values()
        )
        if (
            saturated
            and len(pids) >= 20
            and pulse.is_file()
            and len(pulse.read_text().splitlines()) >= 4
        ):
            break
        if time.monotonic() > deadline:
            diagnostic = {
                "pids": pids,
                "limits": limits,
                "pulse": pulse.read_text() if pulse.is_file() else None,
                "latched": Path("/var/lib/mano-broker/stop-latched").exists(),
                "journal": run(
                    [
                        "journalctl",
                        "--no-pager",
                        "-n",
                        "60",
                        "-u",
                        "mano-stopd-spike.service",
                        "-u",
                        f"mano-stop-{phase}-input.service",
                        "-u",
                        "mano-stop-display.service",
                    ],
                    check=False,
                ).stdout,
            }
            (OUT / "stop-readiness.json").write_text(json.dumps(diagnostic, indent=2) + "\n")
            raise RuntimeError("Bounded process storm/input not ready: " + json.dumps(diagnostic))
        time.sleep(0.05)
    seats = query_seat()
    assert any(seat["capabilities"] & 1 for seat in seats)
    state = {
        "phase": phase,
        "cgroup": str(group),
        "task_pids": pids,
        "pids_limit_events_before": limits,
        "seats_before": seats,
        "pulse_bytes_before": pulse.stat().st_size,
        "grant": grant,
        "core": frozen("mano-rescue-core.service"),
    }
    (BASE / f"{phase}-before.json").write_text(json.dumps(state))
    os.chmod(BASE / f"{phase}-before.json", 0o600)
    return state


def observe(phase):
    # Serial root fixture starts with a cleared environment; source path is fixed.
    sys.path.insert(0, "/opt/mano-lab/src")
    from mano_lab.processes import exited_or_zombie

    def task_diagnostic(pid):
        try:
            lines = Path(f"/proc/{pid}/status").read_text().splitlines()
            return {key: value.strip() for key, value in
                    (line.split(":", 1) for line in lines if ":" in line)
                    if key in {"State", "Uid", "PPid"}}
        except (FileNotFoundError, ProcessLookupError):
            return {"state": "exited"}

    before = json.loads((BASE / f"{phase}-before.json").read_text())
    group = Path(before["cgroup"])
    deadline = time.monotonic() + 15
    while True:
        events = (
            (group / "cgroup.events").read_text() if (group / "cgroup.events").is_file() else None
        )
        empty = not group.exists() or (events is not None and "populated 0" in events)
        surviving = [pid for pid in before["task_pids"] if not exited_or_zombie(pid)]
        if empty and not surviving and Path("/var/lib/mano-broker/stop-latched").exists():
            break
        if time.monotonic() > deadline:
            diagnostic = {
                "group_exists": group.exists(),
                "events": events,
                "latched": Path("/var/lib/mano-broker/stop-latched").exists(),
                "epoch": Path("/var/lib/mano-broker/grant-epoch").read_text(),
                "surviving_pids": surviving,
                "surviving_pid_status": {str(pid): task_diagnostic(pid) for pid in surviving},
                "unit": run(
                    [
                        "systemctl",
                        "show",
                        "mano-stopd-spike.service",
                        "-p",
                        "ActiveState",
                        "-p",
                        "MainPID",
                        "-p",
                        "NRestarts",
                    ],
                    check=False,
                ).stdout,
                "journal": run(
                    ["journalctl", "-u", "mano-stopd-spike.service", "--no-pager", "-n", "25"],
                    check=False,
                ).stdout,
            }
            raise RuntimeError("Stop did not settle: " + json.dumps(diagnostic))
        time.sleep(0.05)
    epoch = int(Path("/var/lib/mano-broker/grant-epoch").read_text())
    assert epoch > before["grant"]["epoch"]
    for pid in before["task_pids"]:
        assert exited_or_zombie(pid), f"Task {pid} survived"
    assert DISPLAY.stat().st_uid == 0 and stat.S_IMODE(DISPLAY.stat().st_mode) == 0o700
    seats = query_seat()
    assert all(not (seat["capabilities"] & 1) for seat in seats)
    pulse = BASE / f"pulse-{phase}.log"
    first = pulse.stat().st_size
    time.sleep(0.2)
    assert pulse.stat().st_size == first
    attacks = []
    daemon_pid = int(prop("mano-stopd-spike.service", "MainPID"))
    assert daemon_pid > 0
    for actor in ("mano-agent", "mano-core", "mano-worker"):
        code = (
            "import os,socket,sys,errno; "
            "\ntry:"
            "\n if sys.argv[1]=='signal': os.kill(int(sys.argv[2]),19)"
            "\n else: s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET); s.connect(sys.argv[2])"
            "\nexcept PermissionError as e: "
            "assert e.errno in {errno.EACCES,errno.EPERM}; sys.exit(0)"
            "\nsys.exit(1)"
        )
        for kind, target in (("signal", str(daemon_pid)), ("socket", str(BASE / "human.sock"))):
            denied = run(
                ["/usr/sbin/runuser", "-u", actor, "--", "python3", "-c", code, kind, target],
                check=False,
            )
            assert denied.returncode == 0
            attacks.append({"actor": actor, "route": kind, "denied": True})
    result = {
        "before": before,
        "cgroup_events_after": (group / "cgroup.events").read_text()
        if group.exists()
        else "cgroup removed",
        "cgroup_removed": not group.exists(),
        "epoch_after": epoch,
        "seats_after": seats,
        "pulse_stopped": True,
        "input_runtime_root_owned": True,
        "actor_denials": attacks,
        "core_after": frozen("mano-rescue-core.service"),
        "authority_after": frozen("mano-approval-spike.service"),
        "stopd_pid": daemon_pid,
        "stopd_restarts": int(prop("mano-stopd-spike.service", "NRestarts")),
    }
    (OUT / f"independent-stop-{phase}.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    assert len(sys.argv) == 2 and sys.argv[1] in {
        "prepare",
        "watchdog",
        "watchdog-status",
        "manual",
        "manual-status",
        "cleanup",
    }
    assert (
        os.getuid() == 0
        and Path("/etc/mano-lab-disposable").read_text().strip() == "mano-phase0-ci"
    )
    assert run(["systemd-detect-virt", "--vm"]).stdout.strip() in {"kvm", "qemu"}
    action = sys.argv[1]
    if action == "cleanup":
        config = BASE / "cgroup-path"
        if config.is_file():
            kill = Path(config.read_text().strip()) / "cgroup.kill"
            if kill.is_file():
                kill.write_text("1")
        run(
            ["systemctl", "kill", "--signal=KILL", "--kill-whom=all", "mano-stopd-spike.service"],
            check=False,
        )
        for unit in ("mano-stopd-spike.service", SLICE, "mano-stop-display.service"):
            run(["systemctl", "stop", unit], check=False)
        (OUT / "stop-kernel-journal.txt").write_text(
            run(["journalctl", "-k", "--no-pager"], check=False).stdout
        )
        printk = BASE / "console-printk-before"
        if printk.is_file():
            Path("/proc/sys/kernel/printk").write_text(printk.read_text())
            printk.unlink()
        for file in (
            BASE / "human.sock",
            BASE / "ever-started",
            BASE / "cgroup-path",
            BASE / "watchdog-before.json",
            BASE / "manual-before.json",
            BASE / "pulse-watchdog.log",
            BASE / "pulse-manual.log",
        ):
            file.unlink(missing_ok=True)
        return
    if action == "prepare":
        BASE.mkdir(mode=0o711, exist_ok=True)
        assert BASE.stat().st_uid == 0 and not BASE.is_symlink()
        # Preserve warning/error console output, keep info in the kernel journal.
        # Slow emulated UART printk can stall RCU while pressure rejects forks.
        printk = Path("/proc/sys/kernel/printk")
        prior = printk.read_text()
        (BASE / "console-printk-before").write_text(prior)
        values = prior.split()
        values[0] = "5"
        printk.write_text(" ".join(values) + "\n")
        run(
            [
                "systemd-run",
                "--unit=mano-stop-display",
                "--property=Type=exec",
                "--uid=mano-agent",
                "--property=PrivateNetwork=yes",
                "--property=RuntimeDirectory=mano-stop-agent",
                "--property=RuntimeDirectoryMode=0700",
                "--setenv=WLR_BACKENDS=headless",
                "--setenv=WLR_RENDERER=pixman",
                "--setenv=WLR_HEADLESS_OUTPUTS=1",
                "--setenv=XDG_RUNTIME_DIR=/run/mano-stop-agent",
                "/usr/bin/sway",
                "-c",
                "/opt/mano-lab/packaging/sway/agent.conf",
            ]
        )
        deadline = time.monotonic() + 10
        while not list(DISPLAY.glob("sway-ipc.*.sock")):
            assert time.monotonic() < deadline
            time.sleep(0.1)
        run(["systemctl", "set-property", SLICE, "TasksMax=64", "MemoryMax=160M", "CPUQuota=60%"])
        run(
            [
                "systemd-run",
                "--unit=mano-stop-anchor",
                f"--slice={SLICE}",
                "--property=Type=exec",
                "--uid=mano-worker",
                "/bin/sleep",
                "600",
            ]
        )
        path = "/sys/fs/cgroup" + prop(SLICE, "ControlGroup")
        (BASE / "cgroup-path").write_text(path + "\n")
        os.chmod(BASE / "cgroup-path", 0o600)
        run(
            [
                "systemd-run",
                "--unit=mano-stopd-spike",
                "--no-block",
                "--property=Type=notify",
                "--property=WatchdogSec=1",
                "--property=Restart=on-failure",
                "--property=RestartSec=0.2",
                "--property=TimeoutAbortSec=1",
                "--property=TimeoutStopSec=1",
                "--property=LimitCORE=0",
                "/usr/local/lib/mano-lab/stopd-probe",
            ]
        )
        deadline = time.monotonic() + 12
        while prop("mano-stopd-spike.service", "ActiveState") != "active":
            if time.monotonic() > deadline:
                diagnostic = run(
                    ["journalctl", "-u", "mano-stopd-spike.service", "--no-pager", "-n", "30"],
                    check=False,
                ).stdout
                (OUT / "stopd-startup.txt").write_text(diagnostic)
                raise RuntimeError("Native stopd startup failed: " + diagnostic)
            time.sleep(0.1)
        phase_start("watchdog")
        run(
            [
                "systemctl",
                "kill",
                "--signal=STOP",
                "--kill-whom=main",
                "mano-approval-spike.service",
            ]
        )
        print(json.dumps({"prepared": True, "authority": frozen("mano-approval-spike.service")}))
        return
    if action == "watchdog":
        original = int(prop("mano-stopd-spike.service", "MainPID"))
        os.kill(original, signal.SIGSTOP)
        result = observe("watchdog")
        assert result["stopd_restarts"] >= 1 and result["stopd_pid"] != original
        result["original_stopd_pid"] = original
        (OUT / "independent-stop-watchdog.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result))
        return
    if action == "watchdog-status":
        run(
            [
                "systemctl",
                "kill",
                "--signal=CONT",
                "--kill-whom=main",
                "mano-approval-spike.service",
            ]
        )
        print((OUT / "independent-stop-watchdog.json").read_text())
        return
    if action == "manual":
        phase_start("manual")
        run(
            [
                "systemctl",
                "kill",
                "--signal=STOP",
                "--kill-whom=main",
                "mano-approval-spike.service",
            ]
        )
        print(json.dumps({"prepared": True, "authority": frozen("mano-approval-spike.service")}))
        return
    result = observe("manual")
    run(["systemctl", "kill", "--signal=CONT", "--kill-whom=main", "mano-approval-spike.service"])
    print(json.dumps(result))


if __name__ == "__main__":
    main()

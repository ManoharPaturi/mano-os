"""Phase 0 probe sandbox only. NOT an authorized production executor.

No model-facing execution API. No broker grants or network capability. This
constructor is exercised only in a disposable Debian lab. Production cgroups,
seccomp/Landlock and authority separation are separate release gates.
"""

import os
import platform
import subprocess
from pathlib import Path

MIN_BWRAP = "0.12.0-1~deb13u1"
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


def require_patched() -> str:
    if platform.system() != "Linux":
        raise RuntimeError("Linux lab required; no unsandboxed fallback")
    release = Path("/etc/os-release").read_text()
    if "ID=debian" not in release or 'VERSION_ID="13"' not in release:
        raise RuntimeError("This spike requires Debian 13")
    version = subprocess.check_output(
        ["dpkg-query", "-W", "-f=${Version}", "bubblewrap"],
        text=True,
        env=ENV,
    ).strip()
    check = subprocess.run(
        ["dpkg", "--compare-versions", version, "ge", MIN_BWRAP],
        env=ENV,
        check=False,
    )
    if check.returncode != 0:
        raise RuntimeError(f"Unsafe bubblewrap {version}; require {MIN_BWRAP}")
    return version


def command(workspace: Path, argv: list[str], gui_socket: Path | None = None) -> list[str]:
    if not argv or any(not isinstance(a, str) or "\x00" in a for a in argv):
        raise ValueError("Expected nonempty argv")
    # Reject symlinks in every component. Owner may still race; disposable lab
    # only. Production will require broker-owned mounts and FD-based resolution.
    original = workspace.absolute()
    if any(p.is_symlink() for p in (original, *original.parents)):
        raise ValueError("Workspace contains symlink")
    workspace = original.resolve(strict=True)
    if not workspace.is_dir() or workspace.stat().st_uid != os.getuid():
        raise ValueError("Workspace must be an owned directory")
    if workspace == Path("/") or workspace in (Path("/etc"), Path("/usr"), Path.home()):
        raise ValueError("Broad host mounts forbidden")
    args = [
        "/usr/bin/bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/sbin",
        "/sbin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/home/task",
        "--dir",
        "/etc",
        "--dir",
        "/run",
        "--dir",
        "/workspace",
        "--bind",
        str(workspace),
        "/workspace",
        "--chdir",
        "/workspace",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/home/task",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--",
        *argv,
    ]
    if gui_socket is not None:
        # Lab-only restricted context socket, never a directory or raw compositor socket.
        gui_socket = gui_socket.absolute()
        if gui_socket.is_symlink() or not gui_socket.is_socket():
            raise ValueError("Expected a real restricted Wayland socket")
        if gui_socket != Path("/run/mano-worker/restricted-wayland"):
            raise ValueError("Raw or unknown display socket forbidden")
        end = args.index("--")
        args[end:end] = [
            "--dir",
            "/run/task",
            "--ro-bind",
            str(gui_socket),
            "/run/task/wayland-0",
            "--setenv",
            "XDG_RUNTIME_DIR",
            "/run/task",
            "--setenv",
            "WAYLAND_DISPLAY",
            "wayland-0",
        ]
    return args


def run_probe(workspace: Path, argv: list[str], timeout: int = 20):
    require_patched()
    if not 1 <= timeout <= 120:
        raise ValueError("Probe timeout outside lab budget")
    return subprocess.run(
        command(workspace, argv),
        env=ENV,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        close_fds=True,
        check=False,
    )

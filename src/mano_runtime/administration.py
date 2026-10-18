"""Fixed Root package lifecycle and explicit human enrollment. No model-selected setup."""

import argparse
import grp
import os
import pwd
import stat
import subprocess
import sys
from pathlib import Path

POLICY = Path("/etc/mano/human.uid")
SOCKETS = (
    "mano-broker.socket",
    "mano-broker-control.socket",
    "mano-broker-provision.socket",
    "mano-approve.socket",
    "mano-launcher-prepare.socket",
    "mano-launcher-control.socket",
    "mano-provider.socket",
    "mano-egress.socket",
    "mano-stopd.socket",
    "mano-stopd-control.socket",
)
UNITS = (
    "mano-runtime.target",
    "mano-controller.timer",
    "mano-controller.service",
    "mano-provider@*.service",
    "mano-egress@*.service",
    "mano-agent-step-*.service",
    "mano-core.slice",
    "mano-launcher.service",
    "mano-broker.service",
    "mano-approve.service",
    *SOCKETS,
    "mano-stopd.service",
)


def root():
    if sys.platform != "linux" or os.getuid() != 0 or os.geteuid() != 0:
        raise PermissionError("Trusted Linux Root administration required")


def command(*argv, timeout=20):
    return subprocess.run(
        argv,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C.UTF-8"},
    )


def trusted_parents(path):
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Untrusted administration parent")


def validate_accounts(*, allow_missing=False):
    accounts = pwd.getpwall()
    for name in ("mano-broker", "mano-provider", "mano-egress"):
        try:
            account = pwd.getpwnam(name)
        except KeyError:
            if not allow_missing:
                raise
            try:
                group = grp.getgrnam(name)
            except KeyError:
                continue
            if (
                group.gr_gid <= 0
                or group.gr_mem
                or any(other.pw_gid == group.gr_gid for other in accounts)
            ):
                raise ValueError("Existing service group is incompatible; group retained") from None
            continue
        group = grp.getgrgid(account.pw_gid)
        if (
            not 0 < account.pw_uid < 1000
            or account.pw_gid <= 0
            or account.pw_dir != "/nonexistent"
            or account.pw_shell != "/usr/sbin/nologin"
            or group.gr_name != name
            or group.gr_mem
            or set(os.getgrouplist(name, account.pw_gid)) != {account.pw_gid}
            or any(
                other.pw_name != name
                and (other.pw_uid == account.pw_uid or other.pw_gid == account.pw_gid)
                for other in accounts
            )
        ):
            raise ValueError("Existing service identity is incompatible; account retained")
        status = command("/usr/bin/passwd", "--status", name).stdout.split()
        if status[:2] != [name, "L"]:
            raise ValueError("Service identity must remain password locked")
    for name in ("mano-human", "mano-request"):
        try:
            group = grp.getgrnam(name)
        except KeyError:
            if allow_missing:
                continue
            raise
        if group.gr_gid <= 0:
            raise ValueError("Non-Root human and request groups required")


def configure_package():
    root()
    validate_accounts(allow_missing=True)
    command("/usr/bin/systemd-sysusers", "/usr/lib/sysusers.d/mano-runtime.conf")
    validate_accounts()
    command("/usr/bin/systemd-tmpfiles", "--create", "/usr/lib/tmpfiles.d/mano-runtime.conf")
    if Path("/run/systemd/system").is_dir():
        command("/usr/bin/systemctl", "daemon-reload")
    print(
        "Runtime installed without starting services. "
        "Enroll an existing human with mano-runtime-setup."
    )


def human_account(name):
    account = pwd.getpwnam(name)
    if (
        account.pw_uid < 1000
        or account.pw_shell in {"/usr/sbin/nologin", "/bin/false"}
        or (account.pw_name.startswith("mano-") and account.pw_name != "mano-human")
    ):
        raise ValueError("An existing non-service Linux login account is required")
    return account


def enroll(name, *, start=False, enable=False):
    root()
    if not os.isatty(0) or not os.isatty(1):
        raise ValueError("Enroll from the trusted Root terminal")
    validate_accounts()
    account = human_account(name)
    trusted_parents(POLICY)
    expected = str(account.pw_uid).encode("ascii") + b"\n"
    try:
        fd = os.open(
            POLICY, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
    except FileExistsError:
        fd = os.open(POLICY, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or os.read(fd, 32) != expected
            ):
                raise ValueError("Human policy already differs or is unsafe; nothing overwritten")
        finally:
            os.close(fd)
    else:
        try:
            if os.write(fd, expected) != len(expected):
                raise ValueError("Uncertain human policy write; inspect before retrying")
            os.fsync(fd)
        finally:
            os.close(fd)
        directory = os.open(POLICY.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    command("/usr/sbin/usermod", "--append", "--groups", "mano-human", "--", account.pw_name)
    if enable:
        command("/usr/bin/systemctl", "enable", "--now", "mano-runtime.target")
    elif start:
        command("/usr/bin/systemctl", "start", "mano-runtime.target")
    print(
        "Human enrolled. Log in again for group membership. "
        "Shipped model, egress and controller defaults are disabled; "
        "existing Root configuration is preserved."
    )


def stop_package(*, remove=False):
    root()
    if not Path("/run/systemd/system").is_dir():
        return
    if remove:
        command("/usr/bin/systemctl", "disable", "mano-runtime.target")
    command("/usr/bin/systemctl", "stop", "mano-controller.timer", "mano-controller.service")
    active = (
        subprocess.run(
            ["/usr/bin/systemctl", "is-active", "--quiet", "mano-stopd.service"],
            check=False,
            timeout=5,
        ).returncode
        == 0
    )
    if active:
        from mano_broker.task_factory import human_uid

        human = pwd.getpwuid(human_uid())
        command("/usr/sbin/runuser", "-u", human.pw_name, "--", "/usr/libexec/mano-stop", timeout=5)
    command("/usr/bin/systemctl", "stop", *UNITS, timeout=40)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Trusted Root runtime package administration")
    parser.add_argument("--configure-package", action="store_true")
    parser.add_argument("--stop-package", action="store_true")
    parser.add_argument("--remove-package", action="store_true")
    parser.add_argument("--enable", action="store_true")
    parser.add_argument("--start", action="store_true")
    parser.add_argument("human", nargs="?")
    args = parser.parse_args(argv)
    try:
        if args.configure_package and not (
            args.stop_package or args.remove_package or args.human or args.start or args.enable
        ):
            configure_package()
        elif (
            (args.stop_package or args.remove_package)
            and not (args.configure_package or args.human or args.start or args.enable)
            and not (args.stop_package and args.remove_package)
        ):
            stop_package(remove=args.remove_package)
        elif args.human and not (
            args.configure_package
            or args.stop_package
            or args.remove_package
            or (args.start and args.enable)
        ):
            enroll(args.human, start=args.start, enable=args.enable)
        else:
            raise ValueError("Choose one fixed administration operation")
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

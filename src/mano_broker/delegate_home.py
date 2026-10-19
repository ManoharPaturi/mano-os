"""Immutable synthetic homes for pinned delegate binaries in the normal sandbox.

The unprivileged launcher worker creates sealed configuration bytes. Bubblewrap
mounts the whole home read-only, with only specific volatile cache/log mounts
writable. No host/global config, authentication store or host environment is used.
"""

import fcntl
import hashlib
import json
import os
import stat
from pathlib import Path

from mano_protocol.delegates import EXECUTABLES, VERSIONS, identify

MANIFEST = Path("/usr/lib/mano-delegates/manifest.json")


def seal_mask():
    return fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL


def trusted_file(path):
    for entry in (path, *path.parents):
        info = entry.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise PermissionError("Untrusted optional delegate installation")
    if not stat.S_ISREG(path.stat().st_mode):
        raise PermissionError("Regular delegate installation file required")


def installed(name):
    trusted_file(MANIFEST)
    data = MANIFEST.read_bytes()
    if len(data) > 16384:
        raise ValueError("Delegate manifest exceeds budget")
    manifest = json.loads(data)
    record = manifest["delegates"][name]
    executable = Path(EXECUTABLES[name])
    trusted_file(executable)
    if record["version"] != VERSIONS[name] or record["executable"] != str(executable):
        raise ValueError("Pinned delegate version changed")
    with executable.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    if digest != record["binary_sha256"] or not executable.stat().st_mode & 0o111:
        raise PermissionError("Pinned delegate binary changed")
    return record


class Home:
    def __init__(self, argv, *, configuration=None):
        self.name = identify(argv)
        self.fd = -1
        if self.name is None:
            return
        installed(self.name)
        if self.name == "antigravity":
            self.directory = ".gemini/antigravity-cli"
            self.filename = "settings.json"
            data = b'{"agentMode":"default","permissions":{"allow":[]}}\n'
            self.volatile = ("conversations", "logs", "cache")
        else:
            self.directory, self.filename = ".codex", "config.toml"
            data = (
                b'approval_policy = "never"\nsandbox_mode = "workspace-write"\n'
                b'cli_auth_credentials_store = "file"\nsqlite_home = "/tmp/mano-codex-state"\n'
            )
            self.volatile = ("sessions", "log", "tmp")
        # Private library injection is for guarded malformed-config contract
        # probes. Public IPC never accepts a config FD, path or override.
        if configuration is not None:
            if not isinstance(configuration, bytes) or len(configuration) > 4096:
                raise ValueError("Bounded synthetic delegate configuration required")
            data = configuration
        seals = seal_mask()
        try:
            self.fd = os.memfd_create("mano-delegate-config", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            if os.write(self.fd, data) != len(data):
                raise OSError("Incomplete synthetic configuration")
            os.lseek(self.fd, 0, os.SEEK_SET)
            fcntl.fcntl(self.fd, fcntl.F_ADD_SEALS, seals)
            if fcntl.fcntl(self.fd, fcntl.F_GET_SEALS) & seals != seals:
                raise PermissionError("Immutable delegate configuration seals missing")
        except BaseException:
            self.close()
            raise

    @property
    def descriptors(self):
        return () if self.fd < 0 else (self.fd,)

    def fragment(self):
        if self.name is None:
            return []
        seals = seal_mask()
        if self.fd < 3 or fcntl.fcntl(self.fd, fcntl.F_GET_SEALS) & seals != seals:
            raise PermissionError("Live sealed synthetic home required")
        home = "/home/task/" + self.directory
        result = ["--tmpfs", "/home/task"]
        parent = Path("/home/task")
        for part in Path(self.directory).parts:
            parent /= part
            result += ["--dir", str(parent)]
        result += [
            "--ro-bind-data",
            str(self.fd),
            home + "/" + self.filename,
            "--tmpfs",
            "/home/task/.cache",
            "--tmpfs",
            "/home/task/.local",
        ]
        for folder in self.volatile:
            result += ["--tmpfs", home + "/" + folder]
        result += [
            "--remount-ro",
            "/home/task",
            "--setenv",
            "CI",
            "1",
            "--setenv",
            "NO_COLOR",
            "1",
            "--setenv",
            "XDG_CACHE_HOME",
            "/home/task/.cache",
        ]
        if self.name == "codex":
            result += ["--setenv", "CODEX_HOME", home]
        return result

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

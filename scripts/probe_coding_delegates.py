#!/usr/bin/env python3
"""Real pinned vendor binaries in a supervised Task UID, no model credentials."""

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

from mano_broker.delegate_home import Home, installed
from mano_broker.runner import run
from mano_broker.sandbox import guard
from mano_protocol.delegates import VERSIONS, command


def main():
    assert os.geteuid() != 0
    assert subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip() in {
        "kvm",
        "qemu",
    }
    workspace = Path(sys.argv[1])
    marker = os.open(workspace / ".delegate-ci-authorized", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(marker)
        assert (
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_gid == os.getegid()
            and stat.S_IMODE(info.st_mode) == 0o640
            and info.st_nlink == 1
        )
        assert os.read(marker, 64) == b"mano-phase0-ci-delegates\n"
    finally:
        os.close(marker)
    root = os.open(workspace, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    cwd = os.open(".", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=root)
    # A fresh CI-only copy permits testing the guard's own rejection paths.
    # The installed /task-guard remains unreadable/unexecutable to applications.
    guard_fixture = workspace / ".mano-ci-native-guard"
    with guard_fixture.open("xb") as target:
        target.write(Path(guard()).read_bytes())
    guard_fixture.chmod(0o555)
    records = {}
    failures = {}
    try:
        for name, version in VERSIONS.items():
            help_text = ""
            try:
                record = installed(name)
                version_result = run(
                    root, cwd, command(name, "version"), timeout=15, revoked=lambda: False
                )
                assert version_result.reason == "completed" and version_result.return_code == 0, (
                    name,
                    version_result.reason,
                    version_result.return_code,
                    version_result.stdout[-2048:],
                    version_result.stderr[-2048:],
                )
                assert version.encode() in version_result.stdout + version_result.stderr
                help_result = run(
                    root, cwd, command(name, "help"), timeout=15, revoked=lambda: False
                )
                assert help_result.reason == "completed" and help_result.return_code == 0, (
                    name,
                    help_result.reason,
                    help_result.return_code,
                    help_result.stderr[-2048:],
                )
                help_text = (help_result.stdout + help_result.stderr).decode(
                    "utf8", errors="replace"
                )
                help_text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", help_text)
                expected_option = "--output-format" if name == "antigravity" else "--sandbox"
                assert expected_option in help_text, (
                    name,
                    "headless help contract",
                    help_text[:8192],
                )
                config_name = (
                    "/home/task/.gemini/antigravity-cli/settings.json"
                    if name == "antigravity"
                    else "/home/task/.codex/config.toml"
                )
                checker = r"""import ctypes,errno,hashlib,json,os,socket,subprocess
from pathlib import Path
p=Path(os.sys.argv[1]);before=p.read_bytes()
assert os.environ['HOME']=='/home/task'
assert not any(key in os.environ for key in ('OPENAI_API_KEY','CODEX_API_KEY','GEMINI_API_KEY',
 'GOOGLE_API_KEY','DISPLAY','WAYLAND_DISPLAY','DBUS_SESSION_BUS_ADDRESS','SSH_AUTH_SOCK'))
assert not Path('/home/mano-human').exists()
for effect in (lambda:p.write_bytes(b'bypass'),lambda:p.unlink(),lambda:p.chmod(0o666),
 lambda:p.parent.rename('/home/task/replaced-config'),
 lambda:Path('/home/task').rename('/tmp/replaced-home')):
 try:effect()
 except OSError as error:
  assert error.errno in {errno.EROFS,errno.EBUSY,errno.EPERM,errno.EACCES,errno.EXDEV}
 else:raise AssertionError('immutable synthetic configuration changed')
assert p.read_bytes()==before
Path('/home/task/.cache/volatile').write_text('allowed')
private='antigravity-cli' in str(p)
if private:
 device_lines=Path('/proc/net/dev').read_text().splitlines()[2:]
 interfaces=[line.split(':')[0].strip() for line in device_lines]
 assert interfaces==['lo']
 listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
 client=socket.socket();client.connect(listener.getsockname());peer,_=listener.accept()
 client.sendall(b'private');assert peer.recv(7)==b'private'
 client.close();peer.close();listener.close()
 for address,allowed in ((('203.0.113.1',9),{errno.ENETUNREACH,errno.EHOSTUNREACH}),
  (('127.0.0.1',int(os.sys.argv[2])),{errno.ECONNREFUSED})):
  with socket.socket() as outbound:
   outbound.settimeout(1)
   try:outbound.connect(address)
   except OSError as error:assert error.errno in allowed,(address,error)
   else:raise AssertionError('private namespace reached outside listener')
 for family,kind in ((socket.AF_INET,socket.SOCK_DGRAM),(socket.AF_NETLINK,socket.SOCK_RAW),
  (socket.AF_PACKET,socket.SOCK_RAW)):
  try:socket.socket(family,kind)
  except PermissionError:pass
  else:raise AssertionError('delegate got non-TCP network socket')
 current=os.stat('/proc/self/ns/net')
 same=subprocess.run(['/workspace/.mano-ci-native-guard','--private-loopback',str(current.st_dev),
  str(current.st_ino),'--','/usr/bin/true'],capture_output=True)
 assert same.returncode==125 and b'private network namespace required' in same.stderr
 assert ctypes.CDLL(None,use_errno=True).unshare(0x40000000)==-1
 assert ctypes.get_errno()==errno.EPERM
 separated=subprocess.run(['/workspace/.mano-ci-native-guard','--','--private-loopback','1','2',
  '/usr/bin/true'],capture_output=True)
 assert separated.returncode==125 and b'guard task exec' in separated.stderr
else:
 try:socket.socket(socket.AF_INET,socket.SOCK_STREAM)
 except PermissionError:pass
 else:raise AssertionError('ordinary delegate got network')
print(json.dumps(dict(config_sha256=hashlib.sha256(before).hexdigest(),immutable_parents=True,
 host_environment_absent=True,external_network_denied=True,volatile_cache_writable=True,
 private_tcp_loopback=private,host_loopback_unreachable=True)))
"""
                with Home(command(name, "version")) as profile:
                    checked = run(
                        root,
                        cwd,
                        ["/usr/bin/python3", "-c", checker, config_name, sys.argv[2]],
                        timeout=5,
                        revoked=lambda: False,
                        home=profile,
                    )
                assert checked.reason == "completed" and checked.return_code == 0, (
                    name,
                    checked.return_code,
                    checked.stderr[-4096:],
                )
                boundaries = json.loads(checked.stdout)
                # Exercise actual vendor parsing of the mounted synthetic config.
                argv = command(
                    name,
                    "run",
                    prompt="Return the word offline; do not change files.",
                    model="mano-ci-no-such-model",
                )
                with Home(
                    argv,
                    configuration=b"{invalid-json" if name == "antigravity" else b"invalid = [",
                ) as invalid:
                    bad = run(root, cwd, argv, timeout=15, revoked=lambda: False, home=invalid)
                bad_text = (bad.stdout + bad.stderr).decode("utf8", errors="replace")
                assert bad.reason == "completed" and bad.return_code != 0, (
                    name,
                    bad.reason,
                    bad_text,
                )
                assert ("settings.json" if name == "antigravity" else "config.toml") in bad_text, (
                    name,
                    bad_text,
                )
                assert any(
                    word in bad_text.lower() for word in ("parse", "invalid", "error", "config")
                )
                records[name] = dict(
                    version=version,
                    binary_sha256=record["binary_sha256"],
                    version_stdout_sha256=hashlib.sha256(version_result.stdout).hexdigest(),
                    help_stdout_sha256=hashlib.sha256(help_result.stdout).hexdigest(),
                    version_exit=0,
                    help_exit=0,
                    help_excerpt=help_text[:8192],
                    boundaries=boundaries,
                    actual_synthetic_config_parse_denial=True,
                    config_denial_stdout_sha256=hashlib.sha256(bad.stdout).hexdigest(),
                    config_denial_stderr_sha256=hashlib.sha256(bad.stderr).hexdigest(),
                    config_denial_excerpt=bad_text[:2048],
                )
            except Exception as error:
                failures[name] = dict(error=repr(error)[:4000], help=help_text[:12000])
        assert not failures, failures
    finally:
        guard_fixture.unlink()
        os.close(root)
        os.close(cwd)
    print(
        json.dumps(
            dict(
                delegates=records,
                authenticated_model_calls=False,
                actual_authenticated_soft_denial=None,
                live_coding_success=False,
                physical_input_provenance=None,
                runtime_package_ships_vendor_binaries=False,
            )
        )
    )


if __name__ == "__main__":
    main()

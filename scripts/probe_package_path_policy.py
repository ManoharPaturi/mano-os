"""Disposable CI mechanism test, not production package confinement evidence.

Only synthetic files under a fresh /run directory are attack targets. No real
interpreter, library, authority record or system configuration is modified.
"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from probe_package_plans import guard

BASE = Path('/run/mano-lab-path-policy')
PROFILE = 'mano-package-path-policy-ci'
POLICY = '''profile mano-package-path-policy-ci flags=(mediate_deleted) {
  /** mr,
  /usr/bin/python3{,.13} ix,
  /run/mano-lab-path-policy/** rwkl,
  deny /run/mano-lab-path-policy/protected/ w,
  deny /run/mano-lab-path-policy/protected/** w,
  deny /run/mano-lab-path-policy/python313.zip w,
}
'''
PROGRAM = r'''
import errno,json,os,subprocess,sys
from pathlib import Path
b=Path('/run/mano-lab-path-policy')
label=Path('/proc/self/attr/current').read_text().strip()
assert label=='mano-package-path-policy-ci (enforce)',label
denials={}
def denied(name,operation):
 try:operation()
 except OSError as e:
  assert e.errno in {errno.EACCES,errno.EPERM},(name,e.errno)
  denials[name]=e.errno
 else:raise AssertionError('Synthetic protected operation succeeded: '+name)
(b/'ordinary/new-file').write_text('ordinary')
(b/'ordinary/new-file').rename(b/'ordinary/renamed')
os.link(b/'ordinary/renamed',b/'ordinary/hardlink')
assert (b/'ordinary/hardlink').read_text()=='ordinary'
denied('existing_file_write',lambda:(b/'protected/python3.13').write_text('changed'))
denied('symlink_unlink',lambda:(b/'protected/python3').unlink())
os.symlink('../ordinary/renamed',b/'ordinary/replacement')
denied('symlink_replace',lambda:os.replace(b/'ordinary/replacement',b/'protected/python3'))
denied('parent_rename',lambda:(b/'protected').rename(b/'relocated'))
denied('hardlink_writable_alias',lambda:os.link(b/'protected/python3.13',b/'ordinary/alias'))
denied('absent_search_entry',lambda:(b/'python313.zip').write_text('changed'))
denied('protected_mode_change',lambda:(b/'protected/python3.13').chmod(0o777))
child=subprocess.run([sys.executable,'-c',
 "from pathlib import Path;import errno;"
 "label=Path('/proc/self/attr/current').read_text().strip();"
 "assert label=='mano-package-path-policy-ci (enforce)';"
 "p=Path('/run/mano-lab-path-policy/protected/python3');"
 "\ntry:p.unlink()\nexcept OSError as e:assert e.errno in {errno.EACCES,errno.EPERM}\n"
 "else:raise AssertionError('Child escaped path policy')"],capture_output=True,text=True,timeout=5)
assert child.returncode==0,(child.stdout,child.stderr)
print(json.dumps(dict(label=label,denials=denials,ordinary_write_rename_link=True,
                     inherited_exec_policy=True)))
'''


def run():
    if sys.platform != 'linux':
        raise PermissionError('Disposable Linux CI only')
    guard()
    assert Path('/sys/module/apparmor/parameters/enabled').read_text().strip() == 'Y'
    assert os.geteuid() == 0
    BASE.mkdir(mode=0o700)  # Refuse reuse; leave evidence in this disposable VM.
    (BASE / 'protected').mkdir(mode=0o700)
    (BASE / 'ordinary').mkdir(mode=0o700)
    payload = b'CI-only synthetic interpreter stand-in\n'
    (BASE / 'protected/python3.13').write_bytes(payload)
    (BASE / 'protected/python3').symlink_to('python3.13')
    original_mode = (BASE / 'protected/python3.13').stat().st_mode & 0o7777
    policy = BASE / 'profile'
    policy.write_text(POLICY)
    policy.chmod(0o600)
    subprocess.run(['/usr/sbin/apparmor_parser', '--add', '--skip-cache', str(policy)],
                   check=True, capture_output=True, timeout=10)
    child = subprocess.run(['/usr/bin/aa-exec', '-p', PROFILE, '--', '/usr/bin/python3',
                            '-c', PROGRAM], capture_output=True, text=True, timeout=15)
    assert child.returncode == 0, (child.stdout[-4096:], child.stderr[-4096:])
    proof = json.loads(child.stdout)
    assert set(proof['denials']) == {'existing_file_write', 'symlink_unlink',
        'symlink_replace', 'parent_rename', 'hardlink_writable_alias',
        'absent_search_entry', 'protected_mode_change'}
    after_payload = (BASE / 'protected/python3.13').read_bytes()
    after_mode = (BASE / 'protected/python3.13').stat().st_mode & 0o7777
    assert after_payload == payload and after_mode == original_mode
    assert os.readlink(BASE / 'protected/python3') == 'python3.13'
    assert not (BASE / 'python313.zip').exists()
    assert not (BASE / 'relocated').exists()
    return dict(scope='synthetic AppArmor path mechanism in disposable CI only',
                production_package_policy_verified=False,
                complete_trusted_runtime_closure_verified=False,
                physical_machine_verified=False, policy_sha256=hashlib.sha256(
                    POLICY.encode()).hexdigest(), proof=proof,
                original_sha256=hashlib.sha256(payload).hexdigest(),
                after_sha256=hashlib.sha256(after_payload).hexdigest(),
                original_mode=original_mode, after_mode=after_mode,
                symlink_target=os.readlink(BASE / 'protected/python3'),
                absent_search_entry_preserved=True, protected_parent_preserved=True)


if __name__ == '__main__':
    print(json.dumps(run(), indent=2))

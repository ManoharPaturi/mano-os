"""Disposable guest orchestration of production GUI/native broker/TTY PAM."""

import hashlib
import json
import os
import pwd
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path('/opt/mano-lab')
OUT = ROOT / 'evidence'
RUNTIME = Path('/run/mano-live-human')


def run(native_terminal, password, register_identity, query, *, config_path=None):
    assert os.geteuid() == 0
    assert Path('/etc/mano-lab-disposable').read_text().strip() == 'mano-phase0-ci'
    assert subprocess.check_output(['systemd-detect-virt', '--vm'], text=True).strip() in {
        'kvm', 'qemu'}
    account = pwd.getpwnam('mano-human')
    RUNTIME.mkdir(mode=0o700)
    os.chown(RUNTIME, account.pw_uid, account.pw_gid)

    def human(*arguments):
        return ['/usr/sbin/runuser', '-u', 'mano-human', '--', 'env', '-i',
                'PATH=/usr/bin:/bin', 'HOME=/home/mano-human', 'LANG=C.UTF-8',
                'PYTHONPATH=/usr/lib/mano-os', 'PYTHONDONTWRITEBYTECODE=1',
                'XDG_RUNTIME_DIR=' + str(RUNTIME), *arguments]

    def wait(check, timeout=25):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = check()
            if value:
                return value
            time.sleep(0.1)
        raise AssertionError('Live GUI/native stage timed out')

    def view():
        path = RUNTIME / 'view.json'
        return json.loads(path.read_text()) if path.exists() else {}

    config = RUNTIME / 'sway.conf'
    config.write_text((config_path or ROOT / 'packaging/sway/human.conf').read_text().replace(
        '/usr/bin/mano-prompt',
        '/usr/bin/python3 /opt/mano-lab/tests/desktop/live_prompt.py').replace(
        '/usr/bin/python3 -m mano_prompt',
        '/usr/bin/python3 /opt/mano-lab/tests/desktop/live_prompt.py'))
    log = (OUT / 'live-human-sway.txt').open('w')
    proc = subprocess.Popen(['/usr/bin/unshare', '--net', *human(
        'WLR_BACKENDS=headless', 'WLR_RENDERER=pixman', 'WLR_HEADLESS_OUTPUTS=1',
        'GSK_RENDERER=cairo', 'GSK_DEBUG=full-redraw', 'WLR_SCENE_DEBUG_DAMAGE=rerender', 'GDK_BACKEND=wayland', 'GTK_A11Y=atspi',
        'dbus-run-session', '--', 'sway', '-c', str(config))], stdout=log, stderr=log)
    ipc = None
    try:
        ipc = wait(lambda: next(RUNTIME.glob('sway-ipc.*.sock'), None))
        subprocess.run(human('SWAYSOCK=' + str(ipc), 'swaymsg',
            'exec /usr/bin/python3 /opt/mano-lab/tests/desktop/live_prompt_contract.py '
            '> /run/mano-live-human/driver.txt 2>&1'),
            check=True, capture_output=True, timeout=10)
        receipt = wait(lambda: view().get('prompt'))
        assert receipt['state'] == 'received' and receipt['task_id'] is None
        factory = subprocess.run(['env', 'PYTHONPATH=/usr/lib/mano-os',
            'PYTHONDONTWRITEBYTECODE=1', 'python3', '-m', 'mano_broker.task_factory'],
            input=json.dumps(dict(prompt_id=receipt['id'])), text=True,
            capture_output=True, timeout=25, check=True)
        managed = json.loads(factory.stdout)['task']
        register_identity(managed['caller_name'])
        assert managed['prompt_id'] == receipt['id']
        (RUNTIME / 'provisioned').touch()
        wait(lambda: (RUNTIME / 'pending-ready').exists())
        pending = view()
        assert pending['prompt']['task_id'] == managed['context']['task_id']
        approval_id = pending['permissions']['approval']['approval_id']
        assert pending['permissions']['status']['automatic'] is False
        # The synthetic guest password stays in this Root/TTY harness only.
        cancelled, cancelled_output = native_terminal('mano_prompt.approve', (approval_id,),
            actor='mano-human', answers=((b'Approve this exact operation?', 'n'),))
        assert cancelled == 0 and b'Approval recorded:' not in cancelled_output
        assert query(dict(mode='permission_status', id=receipt['id']))[
            'profile']['automatic'] is False
        wrong, wrong_output = native_terminal('mano_prompt.approve', (approval_id,),
            actor='mano-human', answers=((b'Approve this exact operation?', 'y'),
                                        (b'OS authentication password:', 'wrong-live-ci')))
        assert wrong == 1 and b'wrong-live-ci' not in wrong_output
        assert query(dict(mode='permission_status', id=receipt['id']))[
            'profile']['automatic'] is False
        native_view = query(dict(mode='view', id=approval_id))['view']
        assert native_view['task_id'] == managed['context']['task_id']
        assert native_view['capability'] == 'policy.set_profile'
        assert native_view['args'] == dict(mode='auto', duration_seconds=120,
            max_actions=3, max_timeout_seconds=10)
        assert native_view['profile_scope']['network'] == 'disabled'
        approved, approved_output = native_terminal('mano_prompt.approve', (approval_id,),
            actor='mano-human', answers=((b'Approve this exact operation?', 'y'),
                                        (b'OS authentication password:', password)))
        assert approved == 0 and b'Approval recorded:' in approved_output
        assert password.encode() not in approved_output
        (RUNTIME / 'approved').touch()
        wait(lambda: (RUNTIME / 'result.json').exists())
        result = json.loads((RUNTIME / 'result.json').read_text())
        assert result['prompt']['id'] == receipt['id']
        assert result['prompt']['task_id'] == managed['context']['task_id']
        result['tty_cancel_wrong_password_then_pam'] = True
        result['artifact_sha256'] = {}
        for name in ('live-permissions-pending.png', 'live-permissions-effective.png'):
            data = (RUNTIME / name).read_bytes()
            result['artifact_sha256'][name] = hashlib.sha256(data).hexdigest()
            (OUT / name).write_bytes(data)
        (OUT / 'live-human-permissions.json').write_text(json.dumps(result, indent=2) + '\n')
        return result
    finally:
        if ipc is not None and proc.poll() is None:
            subprocess.run(human('SWAYSOCK=' + str(ipc), 'swaymsg', 'exit'),
                           timeout=10, check=False, capture_output=True)
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        log.close()
        if (RUNTIME / 'driver.txt').exists():
            shutil.copyfile(RUNTIME / 'driver.txt', OUT / 'live-human-driver.txt')
            print((RUNTIME / 'driver.txt').read_text(), file=sys.stderr)

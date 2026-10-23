"""Disposable Root setup diagnostic: invalid input, never an APT/package effect."""

import json
import subprocess
from pathlib import Path

from probe_package_plans import guard
from probe_package_runtime_closure import collect

ROOT = Path('/opt/mano-lab')
PROPERTIES = (
    'NoNewPrivileges', 'CapabilityBoundingSet', 'AmbientCapabilities', 'ProtectHome', 'PrivateTmp',
    'ProtectKernelTunables', 'ProtectKernelLogs', 'ProtectControlGroups', 'ProtectClock',
    'RestrictRealtime', 'SystemCallArchitectures', 'LockPersonality',
    'MemoryMax', 'TasksMax', 'LimitNOFILE', 'LimitCORE',
)
PROGRAM = '''import importlib.util,json,os,subprocess,time
from pathlib import Path
from mano_runtime.package_apply import sandbox,ENV
from mano_protocol.stop_state import snapshot
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines())
controller_caps={key:int(status[key].strip(),16) for key in
 ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')}
spec=importlib.util.spec_from_file_location('ci_mapped_runtime',
 '/opt/mano-lab/scripts/probe_package_runtime_closure.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
inventory=module.collect()
argv=sandbox([],dict(native_generation=snapshot().generation,expires=time.monotonic()+30))
child=subprocess.run(argv,input=b'{}',capture_output=True,timeout=10,env=ENV,cwd='/')
# The fixed worker rejects {} before cache/commit; no maintainer script can run.
assert len(child.stdout)+len(child.stderr)<8192
print(json.dumps(dict(controller_capabilities=controller_caps,
 mapped_runtime_inventory=inventory,
 controller_run_device=os.stat('/run').st_dev,
 return_code=child.returncode,stdout=child.stdout.decode(errors='replace'),
 stderr=child.stderr.decode(errors='replace'),input='intentionally-invalid-plan')))
'''


def run():
    guard()
    source = subprocess.run(
        ['systemctl', 'show', 'mano-package-apply@setup-ci.service',
         '--property=' + ','.join(PROPERTIES)],
        check=True, capture_output=True, text=True, timeout=5,
    )
    properties = dict(line.split('=', 1) for line in source.stdout.splitlines())
    assert set(properties) == set(PROPERTIES)
    assert properties['NoNewPrivileges'] == 'yes'
    assert 'cap_sys_admin' in properties['CapabilityBoundingSet'].split()
    argv = ['systemd-run', '--quiet', '--pipe', '--wait', '--collect',
            '--unit=mano-package-setup-ci.service', '--slice=mano-package.slice',
            '--property=User=root', '--property=Restart=no',
            '--property=RuntimeMaxSec=15', '--property=KillMode=control-group',
            '--setenv=PYTHONPATH=/usr/lib/mano-os', '--setenv=PYTHONDONTWRITEBYTECODE=1']
    for name, value in properties.items():
        argv.append('--property=' + name + '=' + value)
    argv += ['/usr/bin/python3', '-P', '-c', PROGRAM]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, (result.stdout[-2048:], result.stderr[-2048:])
    value = json.loads(result.stdout)
    # PID1 is observed outside the constrained service. Never add ptrace
    # capabilities to the production controller just to collect CI diagnostics.
    value['outside_observer_mapped_files'] = collect(include_init=True, observer=True)
    value['production_service_properties'] = properties
    (ROOT / 'evidence/package-sandbox-setup.json').write_text(json.dumps(value, indent=2) + '\n')
    # Exact stderr is safe here: no plan, approval, credentials or package script is supplied.
    assert value['return_code'] == 2, value
    frames = value['stdout'].splitlines()
    assert len(frames) == 1 and frames[0].startswith('MANO_PACKAGE_BOUNDARY='), value
    boundary = json.loads(frames[0].split('=', 1)[1])
    flags = set(boundary) - {'namespaces', 'capabilities', 'securebits', 'run_device'}
    assert all(boundary[key] is True for key in flags), value
    assert set(boundary['capabilities']) == {'CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb'}
    assert set(boundary['capabilities'].values()) == {0xdb} and boundary['securebits'] == 43
    assert boundary['run_device'] != value['controller_run_device'], value
    lines = value['stderr'].splitlines()
    assert len(lines) == 1 and lines[0].startswith('MANO_PACKAGE_ERROR='), value
    error = json.loads(lines[0].split('=', 1)[1])
    assert error == dict(stage='admission', error_type='ValueError'), value
    return dict(private_setup_reached_fixed_worker=True, invalid_plan_rejected=True,
                package_execution=False, production_service_properties=properties,
                boundary=boundary)

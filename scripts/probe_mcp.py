"""Installed native-PAM/public-SDK MCP witnesses in disposable Debian only."""

import json
import subprocess
import time
from pathlib import Path

from mano_core.mcp import proposal

CLIENT = """import json,sys,time
from mano_core.broker import BrokerClient
from mano_core.mcp import MCPDiscovery
value=json.load(sys.stdin);client=BrokerClient()
try:
 worker=MCPDiscovery.start(client,proposal=value['proposal'],grant_id=value['grant_id'])
 deadline=time.monotonic()+value['proposal']['args']['timeout_seconds']+12
 while time.monotonic()<deadline:
  state=worker.status()
  if state['state'] in {'done','failed','unknown'}:break
  time.sleep(.15)
 result=worker.result();result['stderr']=result['stderr'].decode('utf8','replace')
 print(json.dumps(dict(action_id=worker.action_id,result=result)))
finally:client.close()
"""


def approve(rpc, human, identity, password, proposed):
    pending = rpc("request", dict(schema_version="1.0", operation="request_approval",
                  body=proposed), actor=identity.name)["approval"]
    assert pending["state"] == "pending"  # Never inherited from Auto/Full profile.
    view = human(dict(mode="view", id=pending["approval_id"]))["view"]
    assert view["args"] == proposed["args"]
    granted = human(dict(mode="confirm", view=view, password=password))
    assert granted["ok"]
    return granted["grant_id"]


def run(rpc, human, identity, password, task, workspace):
    records = {}
    ignored_eof = """import json,sys,time
first=json.loads(sys.stdin.readline())
print(json.dumps(dict(jsonrpc='2.0',id=first['id'],result=dict(
 supportedVersions=['2026-07-28'],capabilities={}))),flush=True)
sys.stdin.read()
time.sleep(60)
"""
    cases = {
        "official-sdk": (["/usr/lib/mano-mcp-ci/bin/python", "-B",
                          "/usr/lib/mano-mcp-ci/server.py"], 20),
        "wrong-id": (["/usr/bin/python3", "-c", "import sys;sys.stdin.readline();"
            "print('{\"jsonrpc\":\"2.0\",\"id\":\"wrong\",\"result\":{}}',flush=True)"], 3),
        "callback": (["/usr/bin/python3", "-c", "import sys;sys.stdin.readline();"
            "print('{\"jsonrpc\":\"2.0\",\"id\":\"request\","
            "\"method\":\"sampling/createMessage\"}',flush=True)"], 3),
        "noise": (["/usr/bin/python3", "-c", "print('not JSON',flush=True)"], 3),
        "quota": (["/usr/bin/python3", "-c", "import sys;"
            "sys.stdout.write('x'*70000);sys.stdout.flush()"], 3),
        "partial": (["/usr/bin/python3", "-c", "import sys;"
            "sys.stdin.readline();sys.stdout.write('{');sys.stdout.flush()"], 3),
        "ignored-eof": (["/usr/bin/python3", "-c", ignored_eof], 2),
        "deadline": (["/usr/bin/python3", "-c", "import os,time;"
            "child=os.fork();os.setsid() if child==0 else None;time.sleep(60)"], 2),
    }
    for name, (argv, timeout) in cases.items():
        proposed = proposal(task_id=task["task_id"], resource_id=task["resource_id"],
            argv=argv, key="mcp-" + name, reason="Inspect untrusted local MCP metadata",
            timeout_seconds=timeout)
        grant = approve(rpc, human, identity, password, proposed)
        response = subprocess.run(["/usr/sbin/runuser", "-u", identity.name, "--", "env",
            "PYTHONPATH=/usr/lib/mano-os", "PYTHONDONTWRITEBYTECODE=1", "python3", "-c", CLIENT],
            input=json.dumps(dict(proposal=proposed, grant_id=grant)), text=True,
            capture_output=True, timeout=timeout+18, check=False)
        assert response.returncode == 0, (name, response.stdout, response.stderr)
        record = json.loads(response.stdout)
        result = record["result"]
        assert result["untrusted"] is True and result["effect_verified"] is False
        assert result["invocation_authorized"] is False
        if name == "official-sdk":
            assert result["status"] == "discovered", result
            assert result["manifest"]["tools"][0]["descriptor"]["name"] == "example"
            assert "run root" in result["manifest"]["tools"][0]["descriptor"]["description"]
            assert "readonly network and host IPC denied" in result["stderr"]
        else:
            assert result["status"] == "failed" and result["manifest"] is None
            assert result["metadata"]["return_code"] == 1
            if name in {"deadline", "ignored-eof"}:
                assert result["metadata"]["reason"] == "timed-out"
        # Completed idempotent replay can only return the original action, never relaunch.
        replay = rpc("request", dict(schema_version="1.0", operation="propose",
                     body=proposed | dict(grant_id=grant)), actor=identity.name)
        assert replay["ok"] and replay["fresh"] is False
        assert replay["action"]["id"] == record["action_id"]
        group = Path("/sys/fs/cgroup/system.slice/mano-launcher.service") / (
            "task-" + record["action_id"])
        assert not group.exists() or "populated 0" in (group / "cgroup.events").read_text()
        query = dict(schema_version="1.0", operation="terminal_output", body=dict(
            task_id=task["task_id"], action_id=record["action_id"]))
        assert rpc("request", query)["ok"] is False
        records[name] = record
    assert not (workspace / "mcp-unauthorized").exists()
    return records


def start_for_stop(rpc, human, identity, password, task):
    # Three sandboxed processes remain alive until native cgroup Stop drains them.
    code = "import os,time;child=os.fork();os.setsid() if child==0 else None;time.sleep(60)"
    proposed = proposal(task_id=task["task_id"], resource_id=task["resource_id"],
        argv=["/usr/bin/python3", "-c", code], key="mcp-frozen-stop",
        reason="Exercise native Stop against MCP discovery", timeout_seconds=60)
    grant = approve(rpc, human, identity, password, proposed)
    response = rpc("request", dict(schema_version="1.0", operation="propose",
                   body=proposed | dict(grant_id=grant)), actor=identity.name)
    assert response["ok"]
    action = response["action"]["id"]
    group = Path("/sys/fs/cgroup/system.slice/mano-launcher.service") / ("task-" + action)
    deadline = time.monotonic()+10
    while time.monotonic() < deadline:
        if group.exists():
            pids = [int(pid) for pid in (group / "cgroup.procs").read_text().split()]
            if len(pids) >= 4:
                return dict(action_id=action, pids=pids)
        time.sleep(.1)
    raise AssertionError("MCP forked server did not start before Stop")

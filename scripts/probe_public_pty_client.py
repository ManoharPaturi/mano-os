#!/usr/bin/env python3
"""Task-UID public SDK witness; invoked only by the guarded Root CI coordinator."""

import json
import sys
import time

from mano_core.broker import BrokerClient
from mano_core.pty import PTYSession

body = json.load(sys.stdin)
client = BrokerClient()
try:
    session = PTYSession(client, **body)
    def read_until(needle):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            time.sleep(0.15)
            session.read()
            if needle in session.output:
                return
        raise AssertionError(bytes(session.output))

    read_until(b'READY\n')
    time.sleep(0.15)
    first = session.write(b'alpha\n', key='first-line')
    assert first == dict(state='acknowledged', written=6, effect_verified=False)
    time.sleep(0.15)
    assert session.write(b'alpha\n', key='first-line') == first
    time.sleep(0.15)
    try:
        session.write(b'beta\n', key='first-line')
    except ValueError:
        pass
    else:
        raise AssertionError('Changed-payload replay accepted')
    time.sleep(0.15)
    assert session.resize(31, 101, key='geometry')['state'] == 'acknowledged'
    time.sleep(0.15)
    assert session.write(b'size\n', key='size-line')['written'] == 5
    read_until(b'SIZE:31:101\n')
    time.sleep(0.15)
    assert session.write(b'\x04', key='eof')['written'] == 1
    read_until(b'END:1\n')
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        time.sleep(0.15)
        result = session.read()
        if result['eof']:
            break
    assert result['eof'] and result['state'] == 'done', result
    assert result['outcome']['reason'] == 'exited' and result['outcome']['return_code'] == 0
    assert session.output.count(b'LINE:alpha\n') == 1
    assert b'beta' not in session.output
    print(json.dumps(dict(public_sdk_interactive=True, native_task_controlling_pty=True,
        replay_once=True, changed_payload_denied=True, resize=True, eof=True,
        output_bytes=len(session.output), output_hex=session.output.hex(), effect_verified=False)))
finally:
    client.close()

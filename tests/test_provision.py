import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mano_broker.ipc import Peer
from mano_broker.protocol import canonical
from mano_broker.provision import provision_task
from mano_broker.registry import Registry
from mano_broker.state import Denied, State


@unittest.skipUnless(sys.platform == "linux", "Linux provisioning descriptors required")
class ProvisionTests(unittest.TestCase):
    def test_root_schema_owner_and_cleanup_before_activation(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            root.mkdir(mode=0o770)
            root.chmod(0o770)
            state = State(base / "state")
            registry = Registry()
            fd = os.open(root, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
            body = dict(
                human_uid=1002, caller_uid=1004, mode="supervised", classification="internal"
            )

            def call(body=body, uid=0):
                return provision_task(
                    state,
                    registry,
                    canonical(
                        dict(schema_version="1.0", operation="provision_task", body=body)
                    ).encode(),
                    peer=Peer(123, uid, uid),
                    directory_fd=fd,
                    boot_id="boot-a",
                )

            try:
                with patch(
                    "mano_broker.provision.pwd.getpwuid",
                    return_value=SimpleNamespace(pw_gid=os.getgid()),
                ):
                    for uid in (1001, 1002, 1004):
                        with self.assertRaises(Denied):
                            call(uid=uid)
                    with self.assertRaises(Denied):
                        call(body | {"path": "/etc"})
                    with self.assertRaises(ValueError):
                        call(body | {"mode": "unsupported"})
                    self.assertEqual(len(registry.resources), 0)
                    root.chmod(0o777)
                    with self.assertRaises(Denied):
                        call()
                    root.chmod(0o770)
                    result = call()
                    self.assertTrue(result["ok"])
                    task = state.db.execute(
                        "SELECT * FROM tasks WHERE id=?", (result["task_id"],)
                    ).fetchone()
                    self.assertEqual(task["resource_id"], result["resource_id"])
                    self.assertEqual(
                        registry.resources[result["resource_id"]].task_id, result["task_id"]
                    )
                    self.assertFalse(
                        os.get_inheritable(registry.resources[result["resource_id"]].workspace.fd)
                    )
            finally:
                os.close(fd)
                registry.close()
                state.close()

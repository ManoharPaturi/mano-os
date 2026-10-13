import os
import sys
import tempfile
import unittest
from pathlib import Path

from mano_broker.resources import Workspace
from mano_broker.state import Denied


@unittest.skipUnless(sys.platform == "linux", "Linux openat2 required")
class ResourcePinTests(unittest.TestCase):
    def test_rename_symlink_type_and_hardlink_boundaries(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "workspace"
            root.mkdir()
            (root / "file").write_text("original")
            outside = base / "outside"
            outside.write_text("protected")
            anchor = os.open(root, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                workspace = Workspace(anchor)
            finally:
                os.close(anchor)
            with workspace:
                with workspace.pin("file") as pinned:
                    old_inode = pinned.inode
                    (root / "file").unlink()
                    (root / "file").symlink_to(outside)
                    self.assertEqual(os.fstat(pinned.fd).st_ino, old_inode)
                    self.assertNotEqual(os.fstat(pinned.fd).st_ino, outside.stat().st_ino)
                with self.assertRaises(OSError):
                    workspace.pin("file")
                for path in ("../outside", str(outside), "a/../file"):
                    with self.assertRaises(ValueError):
                        workspace.pin(path)
                (root / "link").symlink_to(base)
                with self.assertRaises(OSError):
                    workspace.pin("link/outside")
                os.link(outside, root / "hard")
                with self.assertRaises(Denied):
                    workspace.pin("hard")
                os.mkfifo(root / "fifo")
                with self.assertRaises(Denied):
                    workspace.pin("fifo")
                with workspace.pin(".", directory=True):
                    pass
                moved = base / "moved"
                root.rename(moved)
                root.mkdir()
                (root / "new").write_text("replacement")
                (moved / "original").write_text("retained-root")
                with workspace.pin("original") as retained:
                    self.assertEqual(retained.inode, (moved / "original").stat().st_ino)
                with self.assertRaises(OSError):
                    workspace.pin("new")
            with self.assertRaises(Denied):
                workspace.pin("original")

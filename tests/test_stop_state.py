import stat
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from mano_broker.state import Denied
from mano_broker.stop_state import latched, parse


class NativeStopStateTests(unittest.TestCase):
    def read(self, data, **changes):
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_nlink=1,
                               st_size=len(data))
        for name, value in changes.items():
            setattr(info, name, value)
        parent = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        with patch('mano_protocol.stop_state.no_pending'), \
             patch('mano_protocol.stop_state.Path.lstat', return_value=parent), \
             patch('mano_protocol.stop_state.os.open', return_value=77), \
             patch('mano_protocol.stop_state.os.fstat', return_value=info), \
             patch('mano_protocol.stop_state.os.read', return_value=data), \
             patch('mano_protocol.stop_state.os.close') as close:
            try:
                return latched()
            finally:
                close.assert_called_once_with(77)

    def test_valid_armed_and_latched(self):
        self.assertFalse(self.read(b'v1:0:armed\n'))
        self.assertTrue(self.read(b'v1:1:latched\n'))

    def test_corruption_change_or_nonroot_metadata_never_arms(self):
        for data, changes in (
            (b'armed', {}), (b'latched\n', {'st_size': 6}),
            (b'armed\n', {'st_uid': 1004}), (b'armed\n', {'st_nlink': 2}),
            (b'armed\n', {'st_mode': stat.S_IFREG | 0o666}),
        ):
            with self.subTest(data=data, changes=changes), self.assertRaises(Denied):
                self.read(data, **changes)

    def test_generation_encoding_rejects_rollback_ambiguity_and_overflow(self):
        self.assertEqual(parse(b'v1:42:latched\n').generation, 42)
        for value in (b'v1:01:armed\n', b'v1:-1:armed\n',
                      b'v1:9223372036854775808:armed\n', b'v1:1:armed'):
            with self.assertRaises(Denied):
                parse(value)

    def test_pending_native_write_never_reads_armed_authority(self):
        parent = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        with patch('mano_protocol.stop_state.Path.lstat', return_value=parent), \
             patch('mano_protocol.stop_state.os.open') as opening:
            with self.assertRaises(Denied):
                latched()
            opening.assert_not_called()

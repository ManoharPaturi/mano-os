import errno
import os
import types
import unittest
from unittest.mock import patch

from mano_runtime import package_python as python


class PythonMountEvidenceTests(unittest.TestCase):
    def test_busy_executable_is_not_evidence_of_a_readonly_mount(self):
        with patch.object(python.os, 'statvfs', return_value=types.SimpleNamespace(f_flag=0)), \
                patch.object(python.os, 'open', side_effect=OSError(errno.ETXTBSY, 'busy')) as call:
            with self.assertRaisesRegex(PermissionError, 'path is writable'):
                python.verify_readonly('/usr/bin/python3.13')
            call.assert_not_called()

    def test_active_interpreter_write_denial_requires_independent_readonly_flag(self):
        for error in (errno.ETXTBSY, errno.EROFS):
            with self.subTest(error=error), \
                    patch.object(python.os, 'statvfs',
                        return_value=types.SimpleNamespace(f_flag=os.ST_RDONLY)), \
                    patch.object(python.Path, 'is_dir', return_value=False), \
                    patch.object(python.os, 'open', side_effect=OSError(error, 'denied')):
                python.verify_readonly('/usr/bin/python3.13')

    def test_busy_exception_does_not_apply_to_other_files_or_directory_probes(self):
        with patch.object(python.os, 'statvfs',
                return_value=types.SimpleNamespace(f_flag=os.ST_RDONLY)):
            with patch.object(python.Path, 'is_dir', return_value=False), \
                    patch.object(python.os, 'open', side_effect=OSError(errno.ETXTBSY, 'busy')):
                with self.assertRaises(OSError):
                    python.verify_readonly('/usr/bin/unexpected')
            with patch.object(python.Path, 'is_dir', return_value=True), \
                    patch.object(python.os, 'mkdir', side_effect=OSError(errno.ETXTBSY, 'busy')):
                with self.assertRaises(OSError):
                    python.verify_readonly('/usr/lib/python3.13')

    def test_permission_denial_cannot_substitute_for_kernel_readonly_enforcement(self):
        with patch.object(python.os, 'statvfs',
                return_value=types.SimpleNamespace(f_flag=os.ST_RDONLY)), \
                patch.object(python.Path, 'is_dir', return_value=False), \
                patch.object(python.os, 'open', side_effect=OSError(errno.EACCES, 'denied')):
            with self.assertRaises(OSError):
                python.verify_readonly('/usr/bin/python3.13')

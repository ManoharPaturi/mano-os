import array
import hashlib
import os
import socket
import sys
import unittest

from mano_protocol.actions import canonical
from mano_protocol.provider_handoff import receive_response, send_response


@unittest.skipUnless(sys.platform == 'linux' and os.getuid() != 0,
                     'Linux non-root credential and memfd tests required')
class ProviderHandoffTests(unittest.TestCase):
    def setUp(self):
        self.sender, self.receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.sender.settimeout(1)
        self.receiver.settimeout(1)
        self.binding = dict(task_id='a' * 32, action_id='b' * 32, boot_id='boot',
                            nonce='c' * 64, request_sha256='d' * 64)

    def tearDown(self):
        self.sender.close()
        self.receiver.close()

    def receive(self, **changes):
        args = dict(binding=self.binding, expected_uid=os.getuid(), expected_gid=os.getgid())
        return receive_response(self.receiver, **(args | changes))

    def test_large_sealed_response_preserves_bytes_and_closes_received_descriptor(self):
        response = b'x' * 250000
        before = len(os.listdir('/proc/self/fd'))
        send_response(self.sender, response, binding=self.binding)
        self.assertEqual(self.receive(), response)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_wrong_job_nonce_and_kernel_uid_are_denied_without_descriptor_leak(self):
        for changes in (dict(binding=self.binding | {'nonce': 'e' * 64}),
                        dict(expected_uid=os.getuid() + 1)):
            before = len(os.listdir('/proc/self/fd'))
            send_response(self.sender, b'{}', binding=self.binding)
            with self.assertRaises(ValueError):
                self.receive(**changes)
            self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_mutable_and_multiple_descriptors_are_denied_and_closed(self):
        for count in (1, 2):
            fd = os.memfd_create('unsealed-test', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            try:
                os.write(fd, b'{}')
                metadata = canonical(dict(schema_version='1.0', ok=True, binding=self.binding,
                    size=2, sha256=hashlib.sha256(b'{}').hexdigest())).encode()
                before = len(os.listdir('/proc/self/fd'))
                self.sender.sendmsg([metadata], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                                 array.array('i', [fd] * count))])
                with self.assertRaises(ValueError):
                    self.receive()
                self.assertEqual(len(os.listdir('/proc/self/fd')), before)
            finally:
                os.close(fd)

    def test_unbounded_or_malformed_binding_cannot_be_sent(self):
        for packet in (b'', b'x' * 262145):
            with self.assertRaises(ValueError):
                send_response(self.sender, packet, binding=self.binding)
        with self.assertRaises(ValueError):
            send_response(self.sender, b'{}', binding=self.binding | {'nonce': 'bad'})

    def test_truncated_metadata_and_bad_digest_close_even_sealed_descriptors(self):
        import fcntl

        from mano_protocol.provider_handoff import required_seals

        fd = os.memfd_create('sealed-negative-test', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            os.write(fd, b'{}')
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, required_seals())
            bad_digest = canonical(dict(schema_version='1.0', ok=True, binding=self.binding,
                                        size=2, sha256='0' * 64)).encode()
            for metadata in (b'x' * 8193, bad_digest):
                before = len(os.listdir('/proc/self/fd'))
                self.sender.sendmsg([metadata], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                                 array.array('i', [fd]))])
                with self.assertRaises(ValueError):
                    self.receive()
                self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        finally:
            os.close(fd)

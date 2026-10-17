import queue
import socket
import threading
import time
import unittest

from mano_egress.relay import relay


class EgressRelayTests(unittest.TestCase):
    def test_duplex_bytes_and_half_close_are_preserved_without_endpoint_selection(self):
        client, relay_client = socket.socketpair()
        relay_upstream, server = socket.socketpair()
        results = queue.Queue()
        def forward():
            try:
                results.put(relay(relay_client, relay_upstream, deadline=time.monotonic() + 3))
            except BaseException as error:
                results.put(error)
            finally:
                relay_client.close()
                relay_upstream.close()
        def respond():
            request = bytearray()
            try:
                while chunk := server.recv(4096):
                    request.extend(chunk)
                server.sendall(bytes(request)[::-1])
                server.shutdown(socket.SHUT_WR)
            finally:
                server.close()
        forwarding = threading.Thread(target=forward)
        responding = threading.Thread(target=respond)
        with client:
            client.settimeout(4)
            forwarding.start()
            responding.start()
            request = b'opaque-tls-records' * 1000
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            response = bytearray()
            while chunk := client.recv(4096):
                response.extend(chunk)
            self.assertEqual(bytes(response), request[::-1])
        forwarding.join(4)
        responding.join(4)
        self.assertFalse(forwarding.is_alive())
        self.assertFalse(responding.is_alive())
        result = results.get_nowait()
        if isinstance(result, BaseException):
            raise result
        self.assertEqual(result, dict(upstream_bytes=len(request), downstream_bytes=len(request)))

    def test_both_byte_directions_fail_before_forwarding_excess(self):
        for direction in ('client', 'server'):
            client, relay_client = socket.socketpair()
            relay_upstream, server = socket.socketpair()
            with client, relay_client, relay_upstream, server:
                sender = client if direction == 'client' else server
                sender.sendall(b'123456789')
                with self.assertRaises(ValueError):
                    relay(relay_client, relay_upstream, deadline=time.monotonic() + 1,
                          upstream_limit=8, downstream_limit=8)

    def test_absolute_deadline_does_not_wait_for_a_slow_peer(self):
        client, relay_client = socket.socketpair()
        relay_upstream, server = socket.socketpair()
        with client, relay_client, relay_upstream, server:
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                relay(relay_client, relay_upstream, deadline=started + 0.03)
            self.assertLess(time.monotonic() - started, 1)

    def test_nonfinite_or_unbounded_deadline_is_rejected_before_socket_changes(self):
        from unittest.mock import Mock

        for deadline in (True, float('nan'), float('inf'), -1, 2**54,
                         time.monotonic() + 60):
            client, upstream = Mock(), Mock()
            with self.subTest(deadline=deadline), self.assertRaises(ValueError):
                relay(client, upstream, deadline=deadline)
            client.setblocking.assert_not_called()
            upstream.setblocking.assert_not_called()

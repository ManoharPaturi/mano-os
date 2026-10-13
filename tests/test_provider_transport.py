import io
import socket
import ssl
import unittest
from unittest.mock import Mock, patch

from mano_protocol.provider import MAX_RESPONSE
from mano_provider.https import HOST, PATH, PinnedHTTPS, ProviderUnavailable, addresses, generate

PUBLIC = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('93.184.216.34', 443))


class Reply:
    def __init__(self, body=b'{"object":"response"}', *, status=200, headers=None):
        self.body = io.BytesIO(body)
        self.status = status
        self.headers = headers or [('Content-Type', 'application/json'),
                                  ('Content-Length', str(len(body)))]
        self.reads = 0
        self.closed = False

    def getheaders(self):
        return self.headers

    def begin(self):
        pass

    def read1(self, count):
        self.reads += 1
        return self.body.read(count)

    def close(self):
        self.closed = True


class ProviderTransportTests(unittest.TestCase):
    def setUp(self):
        self.args = dict(provider='openai', model='explicit-snapshot', prompt='human goal',
                         max_output_tokens=100)

    def test_resolution_denies_private_mixed_reserved_and_scoped_addresses(self):
        denied = [PUBLIC[:4] + ((ip, 443),) for ip in
                  ('127.0.0.1', '10.0.0.1', '169.254.169.254', '100.64.0.1', '203.0.113.1')]
        denied += [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, '',
                    ('2606:4700:4700::1111', 443, 0, 2))]
        for record in denied:
            with patch('mano_provider.https.socket.getaddrinfo', return_value=[PUBLIC, record]), \
                 patch('mano_provider.https.PinnedHTTPS') as connection:
                with self.assertRaises(ProviderUnavailable):
                    generate(self.args, 'ci-synthetic-key')
                connection.assert_not_called()
        with patch('mano_provider.https.socket.getaddrinfo', return_value=[PUBLIC]) as resolver:
            self.assertEqual(addresses(), [PUBLIC])
            resolver.assert_called_once_with(HOST, 443, type=socket.SOCK_STREAM,
                                             proto=socket.IPPROTO_TCP)

    def test_numeric_connect_retains_fixed_tls_hostname_and_certificate_checks(self):
        context = Mock()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        raw, secure = Mock(), Mock()
        context.wrap_socket.return_value = secure
        with patch('mano_provider.https.ssl.create_default_context', return_value=context), \
             patch('mano_provider.https.socket.socket', return_value=raw), \
             patch('mano_provider.https.time.monotonic', return_value=10):
            connection = PinnedHTTPS(PUBLIC, 40)
            connection.connect()
            raw.connect.assert_called_once_with(('93.184.216.34', 443))
            context.wrap_socket.assert_called_once_with(raw, server_hostname=HOST)
            self.assertIs(connection.sock, secure)
            connection.close()
        context.check_hostname = False
        with patch('mano_provider.https.ssl.create_default_context', return_value=context):
            with self.assertRaises(ProviderUnavailable):
                PinnedHTTPS(PUBLIC, 40)

    def run_reply(self, reply):
        connection = Mock()
        connection.getresponse.return_value = reply
        connection.remaining.return_value = 30
        with patch('mano_provider.https.addresses', return_value=[PUBLIC]), \
             patch('mano_provider.https.PinnedHTTPS', return_value=connection), \
             patch('mano_provider.https.http.client.HTTPResponse', return_value=reply), \
             patch('mano_provider.https.threading.Timer'):
            result = generate(self.args, 'ci-synthetic-key')
        return result, connection

    def test_one_fixed_post_and_bounded_json_response(self):
        reply = Reply()
        result, connection = self.run_reply(reply)
        self.assertEqual(result, b'{"object":"response"}')
        connection.connect.assert_called_once()
        connection.request.assert_called_once()
        call = connection.request.call_args
        self.assertEqual(call.args, ('POST', PATH))
        self.assertEqual(call.kwargs['headers']['Authorization'], 'Bearer ci-synthetic-key')
        self.assertEqual(call.kwargs['headers']['Accept-Encoding'], 'identity')
        self.assertIn(b'"store":false', call.kwargs['body'])
        self.assertTrue(reply.closed)
        connection.close.assert_called_once()

    def test_redirect_errors_framing_truncation_and_oversize_are_not_returned(self):
        cases = [Reply(status=302), Reply(status=500),
            Reply(headers=[('Content-Type', 'text/html')]),
            Reply(headers=[('Content-Type', 'application/json'), ('Content-Encoding', 'gzip')]),
            Reply(headers=[('Content-Type', 'application/json'), ('Content-Length', '1'),
                           ('Content-Length', '1')]),
            Reply(headers=[('Content-Type', 'application/json'), ('Content-Length', '1'),
                           ('Transfer-Encoding', 'chunked')]),
            Reply(headers=[('Content-Type', 'application/json'), ('Content-Length', '1000')]),
            Reply(headers=[('Content-Type', 'application/json'),
                           ('Content-Length', str(MAX_RESPONSE + 1))]),
            Reply(body=b'x' * (MAX_RESPONSE + 1), headers=[('Content-Type', 'application/json')])]
        for reply in cases:
            with self.subTest(headers=reply.headers, status=reply.status):
                with self.assertRaises(ProviderUnavailable):
                    self.run_reply(reply)
                self.assertTrue(reply.closed)

    def test_uncertain_transport_is_not_retried_and_key_errors_are_not_exposed(self):
        connection = Mock()
        connection.remaining.return_value = 30
        connection.request.side_effect = TimeoutError('private credential detail')
        with patch('mano_provider.https.addresses', return_value=[PUBLIC]), \
             patch('mano_provider.https.PinnedHTTPS', return_value=connection), \
             patch('mano_provider.https.threading.Timer'):
            with self.assertRaises(ProviderUnavailable) as caught:
                generate(self.args, 'ci-synthetic-key')
        self.assertNotIn('private', str(caught.exception))
        connection.request.assert_called_once()
        connection.close.assert_called_once()
        with patch('mano_provider.https.addresses') as resolver:
            for key in ('bad\nkey', '', 'x' * 4097):
                with self.assertRaises(ProviderUnavailable):
                    generate(self.args, key)
            with self.assertRaises(ValueError):
                generate(self.args | {'endpoint': 'http://localhost'}, 'ci-synthetic-key')
            resolver.assert_not_called()

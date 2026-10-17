import json
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from mano_provider.https import HOST, ProviderUnavailable, generate


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required for local TLS contract')
class ProviderTLSContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.certs = {}
        for name in (HOST, 'wrong-provider.invalid'):
            cert = Path(cls.temp.name) / (name + '.crt')
            key = Path(cls.temp.name) / (name + '.key')
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=' + name,
                '-addext', 'subjectAltName=DNS:' + name], check=True, timeout=15,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            cls.certs[name] = (cert, key)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def exchange(self, name):
        cert, key = self.certs[name]
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert, key)
        names, requests, failures = [], [], []
        server_context.set_servername_callback(lambda _socket, name, _context: names.append(name))
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        socket_path = Path(self.temp.name) / 'tls.sock'
        listener.bind(str(socket_path))
        listener.listen(1)
        listener.settimeout(5)

        def server():
            try:
                raw, _ = listener.accept()
                raw.settimeout(5)
                with server_context.wrap_socket(raw, server_side=True) as secure, \
                     secure.makefile('rb') as stream:
                    first = stream.readline(8192)
                    headers = {}
                    for _ in range(30):
                        line = stream.readline(8192)
                        if line == b'\r\n':
                            break
                        name, value = line.decode('ascii').split(':', 1)
                        headers[name.lower()] = value.strip()
                    body = stream.read(int(headers['content-length']))
                    requests.append((first, headers, json.loads(body)))
                    result = b'{"object":"response"}'
                    secure.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                        + b'Content-Length: ' + str(len(result)).encode()
                        + b'\r\nConnection: close\r\n\r\n' + result)
            except (OSError, ValueError) as error:
                failures.append(type(error).__name__)

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        # Test-only Unix path, listener-auth and CA injection. Production fixes all three.
        context = ssl.create_default_context(cafile=str(cert))
        args = dict(provider='openai', model='explicit-snapshot', prompt='human goal',
                    max_output_tokens=100)
        try:
            with patch('mano_provider.https.TUNNEL', str(socket_path)), \
                 patch('mano_provider.https.root_listener'), \
                 patch('mano_provider.https.ssl.create_default_context', return_value=context):
                if name == HOST:
                    self.assertEqual(generate(args, 'ci-synthetic-key'), b'{"object":"response"}')
                else:
                    with self.assertRaises(ProviderUnavailable):
                        generate(args, 'ci-synthetic-key')
        finally:
            thread.join(6)
            listener.close()
            socket_path.unlink(missing_ok=True)
        self.assertFalse(thread.is_alive())
        self.assertEqual(names, [HOST])
        return requests, failures

    def test_actual_tls_sni_post_headers_and_body(self):
        requests, failures = self.exchange(HOST)
        self.assertEqual(failures, [])
        self.assertEqual(len(requests), 1)
        first, headers, body = requests[0]
        self.assertEqual(first, b'POST /v1/responses HTTP/1.1\r\n')
        self.assertEqual(headers['host'], HOST)
        self.assertEqual(headers['authorization'], 'Bearer ci-synthetic-key')
        self.assertEqual(body['model'], 'explicit-snapshot')
        self.assertIs(body['store'], False)

    def test_wrong_certificate_hostname_is_denied_before_credentialed_http(self):
        requests, failures = self.exchange('wrong-provider.invalid')
        self.assertEqual(requests, [])
        self.assertEqual(failures, ['SSLError'])

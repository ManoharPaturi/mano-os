"""Fixed OpenAI POST transport; no proxies, redirects or implicit retries."""

import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time

from mano_protocol.actions import ActionRequest, canonical
from mano_protocol.provider import MAX_RESPONSE, request_body

HOST = 'api.openai.com'
PATH = '/v1/responses'
DEADLINE_SECONDS = 30


class ProviderUnavailable(ValueError):
    pass


def addresses():
    resolved = socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    if not resolved or len(resolved) > 32:
        raise ProviderUnavailable('Provider resolution denied')
    for family, kind, protocol, _name, address in resolved:
        ip = ipaddress.ip_address(address[0])
        if (family not in {socket.AF_INET, socket.AF_INET6} or kind != socket.SOCK_STREAM
                or protocol != socket.IPPROTO_TCP or address[1] != 443 or not ip.is_global
                or ip.is_multicast or ip.is_unspecified or ip.is_reserved
                or (family == socket.AF_INET) != (ip.version == 4)
                or (family == socket.AF_INET6 and (address[2] != 0 or address[3] != 0))):
            raise ProviderUnavailable('Provider address denied')
    return resolved


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, address, deadline):
        context = ssl.create_default_context()
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ProviderUnavailable('Provider TLS verification disabled')
        super().__init__(HOST, 443, timeout=DEADLINE_SECONDS, context=context)
        self.address, self.deadline = address, deadline

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ProviderUnavailable('Provider deadline exceeded')
        return remaining

    def connect(self):
        family, kind, protocol, _name, address = self.address
        raw = socket.socket(family, kind, protocol)
        try:
            raw.settimeout(self.remaining())
            raw.connect(address)  # Validated numeric address; no second DNS lookup.
            raw.settimeout(self.remaining())
            self.sock = self._context.wrap_socket(raw, server_hostname=HOST)
            self.sock.settimeout(self.remaining())
        except BaseException:
            raw.close()
            if self.sock is not None:
                self.sock.close()
            raise


def generate(args, credential):
    if (not isinstance(credential, str)
            or not re.fullmatch(r'[A-Za-z0-9._-]{1,4096}', credential)):
        raise ProviderUnavailable('Provider credential unavailable')
    ActionRequest.parse(canonical(dict(schema_version='1.0', task_id='0' * 32,
        grant_id='0' * 32, resource_id='0' * 32, capability='model.plan', args=args,
        idempotency_key='protected-provider-call', reason='Exact approved disclosure')).encode())
    payload = canonical(request_body(args['prompt'], model=args['model'],
                        max_output_tokens=args['max_output_tokens'])).encode()
    deadline = time.monotonic() + DEADLINE_SECONDS
    connection = response = timer = None
    stream = None

    def interrupt():
        if stream is not None:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    try:
        resolved = addresses()
        connection = PinnedHTTPS(resolved[0], deadline)  # One address, one attempt.
        connection.connect()
        stream = connection.sock
        timer = threading.Timer(connection.remaining(), interrupt)
        timer.daemon = True
        timer.start()
        connection.request('POST', PATH, body=payload, headers={
            'Authorization': 'Bearer ' + credential, 'Content-Type': 'application/json',
            'Accept': 'application/json', 'Accept-Encoding': 'identity', 'Connection': 'close'})
        # Own response/socket until bounded reads finish. getresponse() closes
        # the connection reference on Connection: close before the body is read.
        response = http.client.HTTPResponse(stream, method='POST')
        response.begin()
        if response.status != 200:
            raise ProviderUnavailable('Provider response unavailable')  # No error body disclosure.
        headers = response.getheaders()
        lengths = [value for key, value in headers if key.lower() == 'content-length']
        encodings = [value for key, value in headers if key.lower() == 'content-encoding']
        transfers = [value for key, value in headers if key.lower() == 'transfer-encoding']
        types = [value for key, value in headers if key.lower() == 'content-type']
        if (len(lengths) > 1 or len(encodings) > 1 or len(transfers) > 1 or len(types) != 1
                or types[0].split(';')[0].strip().lower() != 'application/json'
                or encodings not in ([], ['identity']) or transfers not in ([], ['chunked'])
                or (transfers and lengths)):
            raise ProviderUnavailable('Provider response framing denied')
        length = None
        if lengths:
            if not re.fullmatch(r'[0-9]{1,7}', lengths[0]):
                raise ProviderUnavailable('Provider length denied')
            length = int(lengths[0])
            if length > MAX_RESPONSE:
                raise ProviderUnavailable('Provider response exceeds budget')
        result = bytearray()
        while True:
            stream.settimeout(connection.remaining())
            chunk = response.read1(min(65536, MAX_RESPONSE + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
            if len(result) > MAX_RESPONSE:
                raise ProviderUnavailable('Provider response exceeds budget')
        connection.remaining()
        if not result or (length is not None and len(result) != length):
            raise ProviderUnavailable('Provider response truncated')
        return bytes(result)
    except (OSError, http.client.HTTPException):
        raise ProviderUnavailable('Provider transport uncertain; no automatic retry') from None
    finally:
        if timer is not None:
            timer.cancel()
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()

"""Fixed OpenAI POST transport; no proxies, redirects or implicit retries."""

import http.client
import re
import socket
import ssl
import threading
import time

from mano_protocol.actions import ActionRequest, canonical
from mano_protocol.provider import MAX_RESPONSE, request_body
from mano_protocol.provider_endpoint import HOST, ProviderUnavailable
from mano_protocol.provider_endpoint import addresses as addresses
from mano_protocol.transport import CREDENTIALS, Peer

TUNNEL = '/run/mano-egress/tls.sock'
PATH = '/v1/responses'
DEADLINE_SECONDS = 30




def root_listener(raw):
    creator = Peer(*CREDENTIALS.unpack(raw.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, CREDENTIALS.size)))
    if creator.pid <= 0 or creator.uid != 0 or creator.gid != 0:
        raise ProviderUnavailable('Egress listener is not Root activated')


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, deadline):
        context = ssl.create_default_context()
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ProviderUnavailable('Provider TLS verification disabled')
        super().__init__(HOST, 443, timeout=DEADLINE_SECONDS, context=context)
        self.deadline = deadline

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ProviderUnavailable('Provider deadline exceeded')
        return remaining

    def connect(self):
        raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            raw.settimeout(self.remaining())
            raw.connect(TUNNEL)
            root_listener(raw)
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
                        max_output_tokens=args['max_output_tokens'],
                        feedback=args.get('feedback'))).encode()
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
        connection = PinnedHTTPS(deadline)  # One fixed Unix tunnel, one attempt.
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

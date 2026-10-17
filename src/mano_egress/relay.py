"""Bounded duplex stream forwarding; owns no TLS keys, DNS or endpoint selection."""

import math
import selectors
import socket
import time

BUFFER = 65536
UPSTREAM_LIMIT = 65536
DOWNSTREAM_LIMIT = 524288


def relay(client, upstream, *, deadline, upstream_limit=UPSTREAM_LIMIT,
          downstream_limit=DOWNSTREAM_LIMIT):
    if (type(upstream_limit) is not int or type(downstream_limit) is not int
            or not 1 <= upstream_limit <= UPSTREAM_LIMIT
            or not 1 <= downstream_limit <= DOWNSTREAM_LIMIT):
        raise ValueError('Invalid stream byte limits')
    if (type(deadline) not in {int, float} or not math.isfinite(deadline)
            or not 0 <= deadline <= 2**53 or deadline - time.monotonic() > 30):
        raise ValueError('Invalid fixed egress deadline')
    sockets = (client, upstream)
    other = {client: upstream, upstream: client}
    pending = {stream: bytearray() for stream in sockets}
    reading = dict.fromkeys(sockets, True)
    half_closed = dict.fromkeys(sockets, False)
    totals = dict.fromkeys(sockets, 0)
    limits = {client: upstream_limit, upstream: downstream_limit}
    for stream in sockets:
        stream.setblocking(False)
    with selectors.DefaultSelector() as selector:
        while True:
            for stream in sockets:
                if not reading[other[stream]] and not pending[stream] and not half_closed[stream]:
                    stream.shutdown(socket.SHUT_WR)
                    half_closed[stream] = True
            if not any(reading.values()) and not any(pending.values()):
                return dict(upstream_bytes=totals[client], downstream_bytes=totals[upstream])
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Fixed egress deadline exceeded')
            for key in list(selector.get_map().values()):
                selector.unregister(key.fileobj)
            for stream in sockets:
                events = 0
                if reading[stream] and len(pending[other[stream]]) < BUFFER:
                    events |= selectors.EVENT_READ
                if pending[stream]:
                    events |= selectors.EVENT_WRITE
                if events:
                    selector.register(stream, events)
            ready = selector.select(remaining)
            if not ready:
                raise TimeoutError('Fixed egress deadline exceeded')
            for key, events in ready:
                stream = key.fileobj
                if events & selectors.EVENT_READ:
                    size = min(16384, BUFFER - len(pending[other[stream]]),
                               limits[stream] + 1 - totals[stream])
                    try:
                        chunk = stream.recv(size)
                    except BlockingIOError:
                        chunk = None
                    if chunk == b'':
                        reading[stream] = False
                    elif chunk is not None:
                        totals[stream] += len(chunk)
                        if totals[stream] > limits[stream]:
                            raise ValueError('Fixed egress byte budget exceeded')
                        pending[other[stream]].extend(chunk)
                if events & selectors.EVENT_WRITE and pending[stream]:
                    try:
                        count = stream.send(pending[stream])
                    except BlockingIOError:
                        continue
                    if count <= 0:
                        raise OSError('Incomplete fixed egress stream')
                    del pending[stream][:count]

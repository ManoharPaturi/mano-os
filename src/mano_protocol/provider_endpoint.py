"""One fixed provider destination and strict public numeric address validation."""

import ipaddress
import socket

HOST = 'api.openai.com'


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


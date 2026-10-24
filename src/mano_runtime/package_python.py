"""Existing Debian13 Python paths protected from package-maintainer writes.

This is one part of runtime protection, not a complete interpreter/ELF closure.
In particular, absent search-path entries and the shared dynamic loader remain
separate requirements. Keep that distinction in native evidence and approvals.
"""

REQUIRED = ('/usr/bin/python3.13', '/usr/lib/python3.13',
            '/usr/lib/python3', '/usr/local')
OPTIONAL = ('/etc/python3', '/etc/python3.13')


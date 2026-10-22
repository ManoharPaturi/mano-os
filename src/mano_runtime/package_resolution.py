"""Root-side read-only re-resolution, held inside coherent package locks.

No installation grant, IPC listener, task launch, download or package commit.
The calculation runs in a fresh Python process with fixed environment/config.
"""

import contextlib
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from mano_broker import package_catalog
from mano_protocol.actions import canonical, unique_object
from mano_protocol.packages import MAX_RESULT, arguments, result
from mano_protocol.stop_state import snapshot
from mano_runtime import recovery
from mano_runtime.package_attempts import boot, guard


def expected(plan):
    if not isinstance(plan, dict):
        raise ValueError("Exact package forecast required")
    args = arguments({key: plan.get(key) for key in ("names", "catalog_id")})
    result(plan, expected=args)
    return args


def isolated(args):
    root = Path(__file__).resolve().parents[1]
    package_catalog.trusted(root, directory=True)
    package_catalog.trusted(Path(__file__))
    packet = subprocess.run(
        ["/usr/bin/python3", "-P", "-m", "mano_runtime.package_resolution", "--worker"],
        input=canonical(args).encode(),
        capture_output=True,
        timeout=60,
        cwd="/",
        env={
            "PATH": "/usr/sbin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "PYTHONPATH": str(root),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )
    if packet.returncode != 0 or packet.stderr or len(packet.stdout) > MAX_RESULT + 1:
        raise ValueError("Independent Root package resolution unavailable")
    return result(json.loads(packet.stdout, object_pairs_hook=unique_object), expected=args)


@contextlib.contextmanager
def current_plan(plan):
    """Yield an exact matching calculation while locks remain held.

    This is an observation, never approval. Future effects still require separate
    exact native PAM, archive/space/checkpoint custody and native Stop admission.
    """
    guard()
    args = expected(plan)
    recovery.layout()
    before = snapshot()
    if before.latched:
        raise PermissionError("Native Stop is latched")
    with recovery.locked():
        package_catalog.load(args["catalog_id"])
        fresh = isolated(args)
        package_catalog.load(args["catalog_id"])
        after = snapshot()
        if after.latched or after.generation != before.generation:
            raise PermissionError("Native Stop changed during Root resolution")
        if canonical(fresh) != canonical(plan):
            raise ValueError("Root resolution differs; fresh package review required")
        yield dict(
            schema_version="1.0",
            plan_sha256=hashlib.sha256(canonical(fresh).encode()).hexdigest(),
            catalog_id=args["catalog_id"],
            status_sha256=fresh["status_sha256"],
            boot_id=boot(),
            stop_generation=after.generation,
            independent_root_resolution=True,
            package_locks_held_in_context=True,
            install_authorized=False,
            approval_authenticated=False,
            effect_verified=False,
            network_used=False,
            maintainer_scripts_executed=False,
        )


def worker():
    guard()
    if sys.argv[1:] != ["--worker"]:
        raise ValueError("Fixed Root resolution worker required")
    raw = sys.stdin.buffer.read(4097)
    if len(raw) > 4096:
        raise ValueError("Root resolution request exceeds budget")
    args = arguments(json.loads(raw, object_pairs_hook=unique_object))
    catalog, _ = package_catalog.load(args["catalog_id"])
    from mano_broker.package_solver import _resolve_catalog

    value = result(
        _resolve_catalog(args["names"], args["catalog_id"], catalog=catalog), expected=args
    )
    package_catalog.load(args["catalog_id"])
    packet = canonical(value).encode()
    if len(packet) > MAX_RESULT:
        raise ValueError("Root resolution output exceeds budget")
    sys.stdout.buffer.write(packet + b"\n")


if __name__ == "__main__":
    try:
        worker()
    except Exception:
        # No raw APT/config/package metadata in an error response.
        sys.exit(2)

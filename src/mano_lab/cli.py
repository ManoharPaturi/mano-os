import argparse
import json
from pathlib import Path

from mano_lab.disk import inspect


def main() -> int:
    parser = argparse.ArgumentParser(description="mano-OS Phase 0 lab utilities")
    sub = parser.add_subparsers(dest="command", required=True)
    disk = sub.add_parser("disk", help="Report storage and large-download stop gate")
    disk.add_argument("path", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args()
    result = inspect(args.path)
    print(json.dumps(result.to_dict(), indent=2))
    return 2 if result.level == "critical" else 0


if __name__ == "__main__":
    raise SystemExit(main())

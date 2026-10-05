"""Command-line interface for pypi-version-bisect.

Two modes:

* ``pypi-version-bisect list <package>`` – print all releases in upload order.
* ``pypi-version-bisect range <package> --check-cmd "..."`` – bisect using an
  external command as the vulnerability oracle. The command is run once per
  candidate version with ``{version}`` substituted in; exit code 0 means the
  version is vulnerable (configurable with ``--vuln-exit-code``).
"""

from __future__ import annotations

import argparse
import logging
import shlex
import subprocess
import sys

from ._core import fetch_all_versions, find_affected_range, format_version_range


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pypi-version-bisect", description=__doc__)
    parser.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="list all releases in chronological order")
    p_list.add_argument("package")

    p_range = sub.add_parser("range", help="bisect the affected version range")
    p_range.add_argument("package")
    p_range.add_argument(
        "--check-cmd",
        required=True,
        help="shell command run per version; use {version} as a placeholder",
    )
    p_range.add_argument("--vuln-exit-code", type=int, default=0, help="exit code that means 'vulnerable' (default 0)")
    p_range.add_argument("--delay", type=float, default=0.5, help="seconds between checks (default 0.5)")
    p_range.add_argument("--max-checks", type=int, default=40, help="hard cap on versions tested (default 40)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    if args.command == "list":
        versions = fetch_all_versions(args.package)
        if not versions:
            print(f"No releases found for {args.package}", file=sys.stderr)
            return 1
        for ver in versions:
            print(ver)
        return 0

    if args.command == "range":
        def check_fn(version: str) -> bool:
            cmd = args.check_cmd.replace("{version}", version)
            completed = subprocess.run(shlex.split(cmd), check=False)  # noqa: S603
            return completed.returncode == args.vuln_exit_code

        result = find_affected_range(
            args.package,
            check_fn,
            delay=args.delay,
            max_checks=args.max_checks,
        )
        if result.get("error"):
            print(f"error: {result['error']}", file=sys.stderr)
            return 1
        print(f"package:        {result['package']}")
        print(f"first_affected: {result['first_affected']}")
        print(f"last_affected:  {result['last_affected']}")
        print(f"fixed_in:       {result['fixed_in']}")
        print(f"checked:        {result['checked_count']} versions")
        print(f"specifier:      {format_version_range(result)}")
        return 0

    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

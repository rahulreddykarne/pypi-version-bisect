"""Binary-search PyPI release history to locate a vulnerable version range.

Given a user-supplied ``check_fn(version) -> bool`` that reports whether a
specific release of a package is vulnerable, :func:`find_affected_range`
discovers the first-affected, last-affected, and fixed-in versions in
``O(log n)`` checks rather than testing every release.
"""

from __future__ import annotations

import logging
import time
from typing import Callable, Optional

import requests

logger = logging.getLogger(__name__)

_PYPI_JSON = "https://pypi.org/pypi/{name}/json"
_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "pypi-version-bisect/0.1 (+https://pypi.org/project/pypi-version-bisect/)"})


def fetch_all_versions(name: str, *, timeout: float = 15.0) -> list[str]:
    """Return all PyPI release versions for *name* in chronological upload order.

    Releases with no uploaded files are skipped. On any network/parse error an
    empty list is returned and a warning is logged.
    """
    try:
        resp = _SESSION.get(_PYPI_JSON.format(name=name), timeout=timeout)
        resp.raise_for_status()
        releases = resp.json().get("releases") or {}
        version_times: list[tuple[str, str]] = []
        for ver, files in releases.items():
            if not files:
                continue
            earliest = min((f.get("upload_time", "") for f in files), default="")
            version_times.append((ver, earliest))
        version_times.sort(key=lambda vt: vt[1])
        return [v for v, _ in version_times]
    except Exception as exc:  # noqa: BLE001 - network failures are non-fatal
        logger.warning("Failed to fetch versions for %s: %s", name, exc)
        return []


def find_affected_range(
    package: str,
    check_fn: Callable[[str], bool],
    *,
    delay: float = 0.5,
    max_checks: int = 40,
) -> dict:
    """Binary-search PyPI release history to find the affected version range.

    Parameters
    ----------
    package:
        PyPI package name.
    check_fn:
        ``Callable(version) -> bool`` returning ``True`` when the version is
        vulnerable. The caller is responsible for installing and testing each
        version however it sees fit (subprocess, container, import, etc.).
    delay:
        Seconds to sleep between ``check_fn`` calls to avoid hammering install
        infrastructure.
    max_checks:
        Hard cap on the number of versions tested. Binary search is
        ``O(log n)``, so the default of 40 covers thousands of releases.

    Returns
    -------
    dict
        Keys: ``package``, ``all_versions``, ``first_affected``,
        ``last_affected``, ``fixed_in``, ``checked_count`` and, on failure,
        ``error``.
    """
    versions = fetch_all_versions(package)
    if not versions:
        return {
            "package": package,
            "all_versions": [],
            "first_affected": None,
            "last_affected": None,
            "fixed_in": None,
            "checked_count": 0,
            "error": "No versions found on PyPI",
        }

    logger.info("version-bisect: %s — %d releases to search", package, len(versions))
    checked = 0
    cached: dict[str, bool] = {}

    def is_affected(ver: str) -> bool:
        nonlocal checked
        if ver in cached:
            return cached[ver]
        if checked >= max_checks:
            raise _MaxChecksExceeded(max_checks)
        if delay:
            time.sleep(delay)
        result = bool(check_fn(ver))
        cached[ver] = result
        checked += 1
        logger.debug("  %s @ %s -> %s", package, ver, "VULN" if result else "safe")
        return result

    last_affected_idx: Optional[int] = None

    # Phase 1: locate the last affected version.
    try:
        if is_affected(versions[-1]):
            last_affected_idx = len(versions) - 1
        else:
            lo, hi = 0, len(versions) - 2
            while lo <= hi:
                mid = (lo + hi) // 2
                if is_affected(versions[mid]):
                    last_affected_idx = mid
                    lo = mid + 1
                else:
                    hi = mid - 1
    except _MaxChecksExceeded:
        pass

    if last_affected_idx is None:
        return {
            "package": package,
            "all_versions": versions,
            "first_affected": None,
            "last_affected": None,
            "fixed_in": None,
            "checked_count": checked,
            "error": "No affected version found in tested sample",
        }

    # Phase 2: binary-search backward to find the first affected version.
    first_affected_idx = last_affected_idx
    lo, hi = 0, last_affected_idx - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        try:
            if is_affected(versions[mid]):
                first_affected_idx = mid
                hi = mid - 1
            else:
                lo = mid + 1
        except _MaxChecksExceeded:
            break

    fixed_in: Optional[str] = None
    if last_affected_idx < len(versions) - 1:
        fixed_in = versions[last_affected_idx + 1]

    return {
        "package": package,
        "all_versions": versions,
        "first_affected": versions[first_affected_idx],
        "last_affected": versions[last_affected_idx],
        "fixed_in": fixed_in,
        "checked_count": checked,
    }


def format_version_range(range_result: dict) -> str:
    """Return a PEP 440-compatible specifier string, e.g. ``>=1.0,<1.5.1``."""
    first = range_result.get("first_affected")
    fixed = range_result.get("fixed_in")
    if first and fixed:
        return f">={first},<{fixed}"
    if first:
        return f">={first}"
    return "unknown"


class _MaxChecksExceeded(RuntimeError):
    """Raised internally when the ``max_checks`` budget is exhausted."""

    def __init__(self, limit: int) -> None:
        super().__init__(f"Exceeded max_checks={limit}")
        self.limit = limit

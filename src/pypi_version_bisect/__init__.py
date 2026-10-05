"""pypi-version-bisect: find a vulnerability's affected version range on PyPI.

Public API
----------
- :func:`fetch_all_versions`  – list a package's releases in upload order.
- :func:`find_affected_range` – binary-search for first/last-affected + fixed.
- :func:`format_version_range` – render a PEP 440 specifier string.
"""

from __future__ import annotations

from ._core import fetch_all_versions, find_affected_range, format_version_range

__all__ = ["fetch_all_versions", "find_affected_range", "format_version_range"]
__version__ = "0.1.0"

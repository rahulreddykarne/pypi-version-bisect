<div align="center">

# pypi-version-bisect

**Binary-search a PyPI package's release history to find the first-affected, last-affected and fixed versions of a vulnerability.**

[![PyPI](https://img.shields.io/pypi/v/pypi-version-bisect?color=blue)](https://pypi.org/project/pypi-version-bisect/)
[![Python](https://img.shields.io/pypi/pyversions/pypi-version-bisect)](https://pypi.org/project/pypi-version-bisect/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Downloads](https://static.pepy.tech/badge/pypi-version-bisect/month)](https://pepy.tech/project/pypi-version-bisect)

</div>

---

Binary-search a PyPI package's release history to pin down **exactly which
versions a vulnerability affects** — the first-affected release, the
last-affected release, and the version that fixed it — using `O(log n)`
tests instead of installing every version.

You supply an oracle (`check_fn(version) -> bool`) that decides whether a given
release is vulnerable. This library handles fetching the release timeline from
PyPI (in chronological upload order) and driving an efficient bisection over it.

## Highlights

- Bring your own oracle: `check_fn(version) -> bool` or an external command
- Releases ordered by real upload time, not string sorting
- `O(log n)` checks with a configurable delay and hard cap
- Emits a ready-to-use specifier such as `>=3.1,<5.4`

## Install

```bash
pip install pypi-version-bisect
```

## Library usage

```python
from pypi_version_bisect import find_affected_range, format_version_range

def check_fn(version: str) -> bool:
    # Install the version in a sandbox and probe for the vulnerability.
    # Return True if vulnerable, False if clean.
    ...

result = find_affected_range("pyyaml", check_fn)
print(result["first_affected"])   # e.g. "3.1"
print(result["last_affected"])    # e.g. "5.3.1"
print(result["fixed_in"])         # e.g. "5.4"
print(format_version_range(result))  # ">=3.1,<5.4"
```

`find_affected_range` returns a dict with `package`, `all_versions`,
`first_affected`, `last_affected`, `fixed_in`, and `checked_count`. If nothing
could be determined it also includes an `error` key.

Tuning knobs:

- `delay` (default `0.5`) — seconds between oracle calls, to be kind to install
  infrastructure.
- `max_checks` (default `40`) — hard cap on oracle calls. Binary search is
  logarithmic, so 40 covers thousands of releases.

## CLI

List releases in upload order:

```bash
pypi-version-bisect list requests
```

Bisect using an external command as the oracle (exit code `0` = vulnerable):

```bash
pypi-version-bisect range examplepkg \
  --check-cmd "python probe.py examplepkg=={version}" \
  --delay 1.0
```

## Notes

- Only depends on `requests`.
- Network failures are non-fatal: fetching returns an empty list and the run
  reports a clear `error` rather than raising.
- Versions are ordered by earliest file upload time, which matches release
  chronology better than string sorting for pre-releases and hotfixes.

## Development

```bash
git clone https://github.com/rahulreddykarne/pypi-version-bisect.git
cd pypi-version-bisect
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
python -m build
```

Bug reports and pull requests are welcome on the [issue tracker](https://github.com/rahulreddykarne/pypi-version-bisect/issues).

## Related projects

Part of a small toolkit for Python supply-chain security research:

| Project | What it does |
| --- | --- |
| [pypi-bulk-download](https://github.com/rahulreddykarne/pypi-bulk-download) | Bulk-download top PyPI packages in parallel with safe unpacking. |
| [tarslip-guard](https://github.com/rahulreddykarne/tarslip-guard) | Detect unsafe extractall() calls and safely extract tar/zip archives. |
| [pypi-blast-radius](https://github.com/rahulreddykarne/pypi-blast-radius) | Estimate the downstream impact of a PyPI package version. |
| [osv-dedupe](https://github.com/rahulreddykarne/osv-dedupe) | Score security findings against published OSV/NVD advisories. |
| [installtime-audit](https://github.com/rahulreddykarne/installtime-audit) | Flag install-time side effects in setup.py and friends. |
| [cvss-estimator](https://github.com/rahulreddykarne/cvss-estimator) | CVSS v3.1 calculator and evidence-driven vector estimator. |

## License

Released under the [MIT License](LICENSE).

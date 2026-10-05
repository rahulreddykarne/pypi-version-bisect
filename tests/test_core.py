from pypi_version_bisect import find_affected_range, format_version_range


def _run(versions, vulnerable_set, **kwargs):
    """Drive find_affected_range against an in-memory version list."""
    checks = {"count": 0}

    def check_fn(v):
        checks["count"] += 1
        return v in vulnerable_set

    # Monkeypatch-free: inject versions via the module's fetch by patching.
    import pypi_version_bisect._core as core

    original = core.fetch_all_versions
    core.fetch_all_versions = lambda name, **_: list(versions)
    try:
        return find_affected_range("demo", check_fn, delay=0, **kwargs)
    finally:
        core.fetch_all_versions = original


def test_contiguous_affected_range():
    versions = ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5"]
    vulnerable = {"1.1", "1.2", "1.3"}
    result = _run(versions, vulnerable)
    assert result["first_affected"] == "1.1"
    assert result["last_affected"] == "1.3"
    assert result["fixed_in"] == "1.4"
    assert format_version_range(result) == ">=1.1,<1.4"


def test_vulnerable_up_to_latest_has_no_fix():
    versions = ["2.0", "2.1", "2.2"]
    vulnerable = {"2.1", "2.2"}
    result = _run(versions, vulnerable)
    assert result["first_affected"] == "2.1"
    assert result["last_affected"] == "2.2"
    assert result["fixed_in"] is None
    assert format_version_range(result) == ">=2.1"


def test_no_affected_version():
    versions = ["1.0", "1.1", "1.2"]
    result = _run(versions, set())
    assert result["first_affected"] is None
    assert result.get("error")


def test_empty_release_history():
    result = _run([], set())
    assert result["error"] == "No versions found on PyPI"


def test_format_unknown():
    assert format_version_range({}) == "unknown"

from roastmywebsite.core.scope import ScopeConfig, host_matches, in_scope


def test_host_matches_exact():
    assert host_matches("example.com", "example.com")
    assert not host_matches("evil.com", "example.com")


def test_host_matches_wildcard():
    assert host_matches("api.example.com", "*.example.com")
    assert host_matches("example.com", "*.example.com")


def test_in_scope_exclude():
    scope = ScopeConfig(include=["example.com"], exclude=["secret.example.com"])
    assert in_scope("example.com", scope)
    assert not in_scope("secret.example.com", scope)
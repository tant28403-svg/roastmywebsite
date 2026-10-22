import tempfile
from pathlib import Path

from roastmywebsite.templating.loader import load_template_file
from roastmywebsite.templating.runner import _matcher_ok
from roastmywebsite.templating.schema import Matcher


def test_load_template_file():
    content = """
id: test-template
info:
  name: Test
  severity: high
requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status: [200]
"""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "t.yaml"
        path.write_text(content, encoding="utf-8")
        template = load_template_file(path)
        assert template is not None
        assert template.id == "test-template"
        assert template.info.severity == "high"


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


def test_matcher_status():
    matcher = Matcher(type="status", status=[200])
    assert _matcher_ok(matcher, FakeResponse(status_code=200), {}) is True
    assert _matcher_ok(matcher, FakeResponse(status_code=404), {}) is False


def test_matcher_word():
    matcher = Matcher(type="word", words=["hello", "world"])
    assert _matcher_ok(matcher, FakeResponse(text="hello world"), {}) is True
    assert _matcher_ok(matcher, FakeResponse(text="hello"), {}) is False


def test_matcher_regex():
    matcher = Matcher(type="regex", regex=[r"secret=\w+"])
    assert _matcher_ok(matcher, FakeResponse(text="secret=abc"), {}) is True
    assert _matcher_ok(matcher, FakeResponse(text="nothing"), {}) is False
from datetime import datetime

from roastmywebsite.core.models import Finding, ScanResult, Severity


def test_scan_result_counts():
    finding = Finding(id="1", title="t", severity=Severity.HIGH, asset="a", module="m")
    result = ScanResult(id="s", target="t", started_at=datetime.utcnow(), findings=[finding])
    assert result.counts["high"] == 1
    assert result.counts["critical"] == 0
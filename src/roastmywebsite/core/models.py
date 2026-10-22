from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Evidence(BaseModel):
    request: str | None = None
    response: str | None = None
    note: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    confidence: float = 1.0
    asset: str
    module: str
    description: str = ""
    evidence: Evidence = Field(default_factory=Evidence)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)


class Asset(BaseModel):
    value: str
    asset_type: str
    source: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    id: str
    target: str
    started_at: datetime
    finished_at: datetime | None = None
    mode: str = "safe"
    assets: list[Asset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts
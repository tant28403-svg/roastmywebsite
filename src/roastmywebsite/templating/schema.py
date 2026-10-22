from __future__ import annotations

from pydantic import BaseModel, Field


class TemplateInfo(BaseModel):
    name: str = ""
    author: str = ""
    severity: str = "info"
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    reference: list[str] = Field(default_factory=list)


class Matcher(BaseModel):
    type: str
    condition: str = "and"
    part: str = "body"
    status: list[int] = Field(default_factory=list)
    words: list[str] = Field(default_factory=list)
    regex: list[str] = Field(default_factory=list)
    size: list[int] = Field(default_factory=list)
    negative: bool = False


class Extractor(BaseModel):
    type: str
    name: str = ""
    part: str = "body"
    regex: list[str] = Field(default_factory=list)
    group: int = 1


class RequestSpec(BaseModel):
    method: str = "GET"
    path: list[str] = Field(default_factory=lambda: ["{{BaseURL}}"])
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    matchers: list[Matcher] = Field(default_factory=list)
    matchers_condition: str = "and"
    extractors: list[Extractor] = Field(default_factory=list)


class Template(BaseModel):
    id: str
    info: TemplateInfo = Field(default_factory=TemplateInfo)
    requests: list[RequestSpec] = Field(default_factory=list)
    variables: dict[str, str] = Field(default_factory=dict)

    @property
    def severity(self) -> str:
        return self.info.severity.lower()
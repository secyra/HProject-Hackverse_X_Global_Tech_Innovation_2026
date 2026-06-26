from pydantic import BaseModel
from typing import Any


class UrlAnalyzePayload(BaseModel):
    url: str
    deep: bool = False


class TelemetryAnalyzePayload(BaseModel):
    telemetry: dict[str, Any] = {}

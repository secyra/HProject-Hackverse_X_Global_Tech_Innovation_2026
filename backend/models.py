from pydantic import BaseModel
from typing import Optional, Any


class UrlAnalyzePayload(BaseModel):
    url: str
    deep: bool = False


class TelemetryAnalyzePayload(BaseModel):
    telemetry: dict[str, Any] = {}
    screenshot: Optional[str] = None

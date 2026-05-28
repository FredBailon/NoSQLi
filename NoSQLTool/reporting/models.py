from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class ReportDocument:
    report_id: str
    title: str
    kind: str
    format: str
    content_type: str
    content: str
    created_at: datetime
    filename: str

    @property
    def route(self) -> str:
        return f"/reports/{self.report_id}"

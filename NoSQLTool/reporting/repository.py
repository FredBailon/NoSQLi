from threading import Lock
from typing import Dict, List, Optional, Protocol

from .models import ReportDocument


class ReportRepository(Protocol):
    def save(self, report: ReportDocument) -> None:
        ...

    def get(self, report_id: str) -> Optional[ReportDocument]:
        ...

    def list_all(self) -> List[ReportDocument]:
        ...


class InMemoryReportRepository:
    def __init__(self) -> None:
        self._reports: Dict[str, ReportDocument] = {}
        self._lock = Lock()

    def save(self, report: ReportDocument) -> None:
        with self._lock:
            self._reports[report.report_id] = report

    def get(self, report_id: str) -> Optional[ReportDocument]:
        with self._lock:
            return self._reports.get(report_id)

    def list_all(self) -> List[ReportDocument]:
        with self._lock:
            return sorted(
                self._reports.values(),
                key=lambda report: report.created_at,
                reverse=True,
            )

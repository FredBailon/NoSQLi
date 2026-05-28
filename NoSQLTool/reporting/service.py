from datetime import datetime
from typing import Dict, Iterable, List, Optional
from uuid import uuid4

from ..detection.detection import TestResult
from ..exploitation.exploitation import ExploitationResult
from .models import ReportDocument
from .renderers import (
    DetectionJsonRenderer,
    DetectionReportRenderer,
    DetectionTextRenderer,
    ExploitationJsonRenderer,
    ExploitationReportRenderer,
    ExploitationTextRenderer,
)
from .repository import ReportRepository


class ReportService:
    def __init__(
        self,
        repository: ReportRepository,
        detection_renderers: Optional[Iterable[DetectionReportRenderer]] = None,
        exploitation_renderers: Optional[Iterable[ExploitationReportRenderer]] = None,
    ) -> None:
        self._repository = repository
        self._detection_renderers = self._index_renderers(
            detection_renderers or [DetectionJsonRenderer(), DetectionTextRenderer()]
        )
        self._exploitation_renderers = self._index_renderers(
            exploitation_renderers
            or [ExploitationJsonRenderer(), ExploitationTextRenderer()]
        )

    def create_detection_report(
        self,
        format_name: str,
        results: List[TestResult],
        summary: Dict[str, Dict[str, List[str]]],
        metadata: dict,
    ) -> ReportDocument:
        renderer = self._get_renderer(self._detection_renderers, format_name)
        created_at = datetime.now()
        content = renderer.render(results, summary, metadata)
        report = self._build_document(
            title="Reporte de deteccion NoSQL",
            kind="detection",
            renderer=renderer,
            content=content,
            created_at=created_at,
        )
        self._repository.save(report)
        return report

    def create_exploitation_report(
        self,
        format_name: str,
        results: List[ExploitationResult],
        metadata: Optional[dict],
    ) -> ReportDocument:
        renderer = self._get_renderer(self._exploitation_renderers, format_name)
        created_at = datetime.now()
        content = renderer.render(results, metadata)
        report = self._build_document(
            title="Reporte de explotacion NoSQL",
            kind="exploitation",
            renderer=renderer,
            content=content,
            created_at=created_at,
        )
        self._repository.save(report)
        return report

    @staticmethod
    def _index_renderers(renderers: Iterable[object]) -> Dict[str, object]:
        return {renderer.format: renderer for renderer in renderers}

    @staticmethod
    def _get_renderer(renderers: Dict[str, object], format_name: str) -> object:
        normalized = format_name.lower().strip()
        if normalized not in renderers:
            allowed = ", ".join(sorted(renderers.keys()))
            raise ValueError(f"Formato de reporte no soportado: {format_name}. Usa: {allowed}")
        return renderers[normalized]

    @staticmethod
    def _build_document(
        title: str,
        kind: str,
        renderer: object,
        content: str,
        created_at: datetime,
    ) -> ReportDocument:
        timestamp = created_at.strftime("%Y%m%d_%H%M%S")
        report_id = uuid4().hex
        return ReportDocument(
            report_id=report_id,
            title=title,
            kind=kind,
            format=renderer.format,
            content_type=renderer.content_type,
            content=content,
            created_at=created_at,
            filename=f"nosql_{kind}_{timestamp}.{renderer.extension}",
        )

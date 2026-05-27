"""Interfaz y selector de estrategias de detección NoSQL."""

from abc import ABC, abstractmethod
from typing import Optional, Tuple

from .base_analysis import BooleanBasedAnalyzer, ResponseInfo, TimeBasedAnalyzer


class NoSQLEngineStrategy(ABC):
    """Interfaz base para estrategias especializadas de detección por motor NoSQL.

    Cada estrategia define cómo generar payloads modificados y cómo analizar
    respuestas para su motor específico.
    """

    @abstractmethod
    def generate_boolean_pair(self, payload: str) -> Tuple[Optional[str], Optional[str]]:
        """Genera variantes TRUE y FALSE de un payload."""
        pass

    @abstractmethod
    def generate_neutral_payload(self, payload: str) -> str:
        """Genera una versión neutral/sin condiciones del payload."""
        pass

    def analyze_error_based(self, baseline: ResponseInfo, injected: ResponseInfo) -> Tuple[bool, Optional[str]]:
        """Análisis genérico de inyección basada en errores."""
        if baseline.status_code < 500 <= injected.status_code:
            return True, "error-based: 5xx nuevo en respuesta"

        if baseline.status_code != injected.status_code and baseline.status_code != 0:
            return True, "error-based: cambio de status code"

        return False, None

    def analyze_time_based(self, baseline: ResponseInfo, injected: ResponseInfo) -> Tuple[bool, Optional[str]]:
        """Análisis de inyección basada en tiempo."""
        return TimeBasedAnalyzer.analyze(baseline, injected)

    def analyze_boolean_based(
        self,
        baseline: ResponseInfo,
        injected: ResponseInfo,
        payload: str,
    ) -> Tuple[bool, Optional[str]]:
        """Análisis básico de inyección boolean-based."""
        return BooleanBasedAnalyzer.analyze_basic(baseline, injected, payload)

    def analyze_boolean_based_advanced(
        self,
        neutral: ResponseInfo,
        true_injected: ResponseInfo,
        false_injected: ResponseInfo,
    ) -> Tuple[bool, Optional[str]]:
        """Análisis avanzado boolean-based."""
        return BooleanBasedAnalyzer.analyze_advanced(neutral, true_injected, false_injected)

    def supports_body_raw_payloads(self) -> bool:
        """Indica si el motor requiere probar payloads como cuerpo JSON completo."""
        return False


def get_engine_strategy(engine: str) -> NoSQLEngineStrategy:
    """Obtiene la estrategia especializada para un motor NoSQL."""
    engine_lower = engine.lower()

    if "couchdb" in engine_lower or "couch" in engine_lower:
        from .couchdb_detection import CouchDBStrategy

        return CouchDBStrategy()

    if "mongodb" in engine_lower or "mongo" in engine_lower:
        from .mongodb_detection import MongoDBStrategy

        return MongoDBStrategy()

    if "neo4j" in engine_lower:
        from .neo4j_detection import Neo4jStrategy

        return Neo4jStrategy()

    raise ValueError(
        f"Motor NoSQL no soportado: {engine}. "
        "Use un motor conocido o cree una estrategia personalizada."
    )

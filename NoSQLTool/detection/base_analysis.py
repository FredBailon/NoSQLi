"""Análisis genérico de respuestas para detección de inyecciones NoSQL.

Este módulo contiene la lógica común de análisis que es agnóstica del motor NoSQL.
Cada estrategia puede extender o personalizar estos métodos.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from difflib import SequenceMatcher
import json


@dataclass
class ResponseInfo:
    status_code: int
    body: str
    elapsed: float


# Constantes genéricas de análisis (no específicas de un motor)
DEFAULT_TIME_BASED_MIN_DELAY_SECONDS = 1.0
DEFAULT_TIME_BASED_MIN_FACTOR = 2.0
DEFAULT_BOOLEAN_BASED_DIFF_RATIO = 0.35
DEFAULT_SIMILAR_STATUS_REQUIRED = 1.0
DEFAULT_SIMILAR_LEN_DIFF_MAX = 0.2
DEFAULT_SIMILAR_TEXT_MIN = 0.8
DEFAULT_DIFFERENT_STATUS_ALLOWED = 0.0
DEFAULT_DIFFERENT_LEN_DIFF_MIN = 0.1
DEFAULT_DIFFERENT_TEXT_MAX = 0.85


class ResponseAnalyzer:
    """Herramientas para analizar y comparar respuestas HTTP."""

    @staticmethod
    def relative_body_diff(base_len: int, inj_len: int) -> float:
        """Calcula la diferencia relativa de longitud entre dos respuestas."""
        denominator = max(base_len, 1)
        return abs(inj_len - base_len) / denominator

    @staticmethod
    def json_structure_signature(obj) -> Optional[str]:
        """Obtiene una firma estructural de un objeto JSON sin valores."""
        if isinstance(obj, dict):
            keys = sorted(obj.keys())
            return f"dict:{','.join(keys)}"
        elif isinstance(obj, list):
            return f"list:{len(obj)}"
        elif isinstance(obj, str):
            return "str"
        elif isinstance(obj, (int, float)):
            return "num"
        elif isinstance(obj, bool):
            return "bool"
        elif obj is None:
            return "null"
        return None

    @staticmethod
    def text_similarity(text1: str, text2: str) -> float:
        """Calcula similitud de texto normalizado (0.0 a 1.0)."""
        norm1 = text1.lower().replace(" ", "").replace("\n", "")
        norm2 = text2.lower().replace(" ", "").replace("\n", "")

        if not norm1 and not norm2:
            return 1.0
        if not norm1 or not norm2:
            return 0.0

        matcher = SequenceMatcher(None, norm1, norm2)
        return matcher.ratio()

    @staticmethod
    def compare_responses(reference: ResponseInfo, candidate: ResponseInfo) -> Dict[str, float]:
        """Compara dos respuestas y retorna métricas normalizadas.

        Returns:
            Dict con:
            - status_match: 1.0 si igual, 0.0 si diferente
            - len_diff_ratio: diferencia relativa de longitudes
            - text_similarity: similitud de texto (0.0 a 1.0)
            - json_structure_similarity: similitud estructural (0.0 a 1.0) o None
        """
        metrics: Dict[str, float] = {}

        # Comparación de status code
        metrics["status_match"] = 1.0 if reference.status_code == candidate.status_code else 0.0

        # Comparación de longitud
        ref_len = len(reference.body)
        cand_len = len(candidate.body)
        metrics["len_diff_ratio"] = ResponseAnalyzer.relative_body_diff(ref_len, cand_len)

        # Similitud de texto
        metrics["text_similarity"] = ResponseAnalyzer.text_similarity(reference.body, candidate.body)

        # Similitud estructura JSON
        try:
            ref_json = json.loads(reference.body)
            cand_json = json.loads(candidate.body)

            ref_sig = ResponseAnalyzer.json_structure_signature(ref_json)
            cand_sig = ResponseAnalyzer.json_structure_signature(cand_json)

            metrics["json_structure_similarity"] = 1.0 if ref_sig == cand_sig else 0.0
        except (json.JSONDecodeError, TypeError, ValueError):
            metrics["json_structure_similarity"] = None

        return metrics

    @staticmethod
    def is_response_similar(
        reference: ResponseInfo, candidate: ResponseInfo, thresholds: Optional[Dict[str, float]] = None
    ) -> bool:
        """Determina si una respuesta es similar a la referencia basado en thresholds."""
        if thresholds is None:
            thresholds = {
                "status_match": DEFAULT_SIMILAR_STATUS_REQUIRED,
                "len_diff_ratio": DEFAULT_SIMILAR_LEN_DIFF_MAX,
                "text_similarity": DEFAULT_SIMILAR_TEXT_MIN,
            }

        metrics = ResponseAnalyzer.compare_responses(reference, candidate)

        return (
            metrics["status_match"] >= thresholds.get("status_match", DEFAULT_SIMILAR_STATUS_REQUIRED)
            and metrics["len_diff_ratio"] <= thresholds.get("len_diff_ratio", DEFAULT_SIMILAR_LEN_DIFF_MAX)
            and metrics["text_similarity"] >= thresholds.get("text_similarity", DEFAULT_SIMILAR_TEXT_MIN)
        )

    @staticmethod
    def is_response_different(
        reference: ResponseInfo, candidate: ResponseInfo, thresholds: Optional[Dict[str, float]] = None
    ) -> bool:
        """Determina si una respuesta es diferente de la referencia basado en thresholds."""
        if thresholds is None:
            thresholds = {
                "status_match": DEFAULT_DIFFERENT_STATUS_ALLOWED,
                "len_diff_ratio": DEFAULT_DIFFERENT_LEN_DIFF_MIN,
                "text_similarity": DEFAULT_DIFFERENT_TEXT_MAX,
            }

        metrics = ResponseAnalyzer.compare_responses(reference, candidate)

        return (
            metrics["status_match"] <= thresholds.get("status_match", DEFAULT_DIFFERENT_STATUS_ALLOWED)
            or metrics["len_diff_ratio"] >= thresholds.get("len_diff_ratio", DEFAULT_DIFFERENT_LEN_DIFF_MIN)
            or metrics["text_similarity"] <= thresholds.get("text_similarity", DEFAULT_DIFFERENT_TEXT_MAX)
        )


class TimeBasedAnalyzer:
    """Análisis específico para inyecciones basadas en tiempo."""

    MIN_DELAY_SECONDS = DEFAULT_TIME_BASED_MIN_DELAY_SECONDS
    MIN_FACTOR = DEFAULT_TIME_BASED_MIN_FACTOR

    @staticmethod
    def analyze(
        baseline: ResponseInfo, injected: ResponseInfo, min_delay_seconds: float = None, min_factor: float = None
    ) -> Tuple[bool, Optional[str]]:
        """Analiza si hay indicios de inyección time-based.

        Args:
            baseline: Respuesta sin inyección
            injected: Respuesta con payload inyectado
            min_delay_seconds: Mínimo delay en segundos (default: 1.0)
            min_factor: Factor mínimo de aumento (default: 2.0)

        Returns:
            Tupla (vulnerable, reason)
        """
        if min_delay_seconds is None:
            min_delay_seconds = TimeBasedAnalyzer.MIN_DELAY_SECONDS
        if min_factor is None:
            min_factor = TimeBasedAnalyzer.MIN_FACTOR

        delta = injected.elapsed - baseline.elapsed
        threshold = max(min_delay_seconds, baseline.elapsed * min_factor)

        # Si el delta supera el umbral, reportar incluso cuando la respuesta inyectada
        # termine en timeout (status_code=0), ya que puede ser señal de sleep efectivo.
        if delta >= threshold:
            if injected.status_code == 0:
                lower_body = (injected.body or "").lower()
                timeout_hint = "timed out" in lower_body or "timeout" in lower_body
                if timeout_hint:
                    return True, (
                        "Posible inyeccion time-based: timeout tras delay "
                        f"{delta:.2f}s (baseline: {baseline.elapsed:.2f}s)"
                    )

            return True, f"Posible inyeccion time-based: delay {delta:.2f}s (baseline: {baseline.elapsed:.2f}s)"

        return False, None


class BooleanBasedAnalyzer:
    """Análisis específico para inyecciones basadas en operadores booleanos."""

    DIFF_RATIO = DEFAULT_BOOLEAN_BASED_DIFF_RATIO

    @staticmethod
    def infer_boolean_intent(payload: str) -> Optional[str]:
        """Infiere si el payload intenta representar una condición TRUE o FALSE."""
        normalized = payload.lower().replace(" ", "")
        true_markers = ("or1=1", "'1'='1'", "true")
        false_markers = ("or1=0", "'1'='0'", "false")

        if any(marker in normalized for marker in true_markers):
            return "true"
        if any(marker in normalized for marker in false_markers):
            return "false"
        return None

    @staticmethod
    def analyze_basic(
        baseline: ResponseInfo, injected: ResponseInfo, payload: str, diff_ratio: float = None
    ) -> Tuple[bool, Optional[str]]:
        """Análisis básico de inyección boolean-based.

        Args:
            baseline: Respuesta sin inyección
            injected: Respuesta con payload inyectado
            payload: El payload utilizado
            diff_ratio: Diferencia relativa de longitud mínima que indica vulnerabilidad

        Returns:
            Tupla (vulnerable, reason)
        """
        if diff_ratio is None:
            diff_ratio = BooleanBasedAnalyzer.DIFF_RATIO

        base_len = len(baseline.body)
        inj_len = len(injected.body)
        diff = ResponseAnalyzer.relative_body_diff(base_len, inj_len)
        intent = BooleanBasedAnalyzer.infer_boolean_intent(payload)

        if baseline.status_code != injected.status_code:
            return True, "boolean-based: cambio de codigo HTTP"

        if intent == "true" and base_len > 0 and inj_len >= int(base_len * 1.2):
            return True, f"boolean-based: condicion TRUE altera resultado (len: {base_len} -> {inj_len})"

        if intent == "false" and base_len > 0 and inj_len <= int(base_len * 0.8):
            return True, f"boolean-based: condicion FALSE altera resultado (len: {base_len} -> {inj_len})"

        if diff >= diff_ratio:
            return True, f"boolean-based: diferencia relevante ({diff:.2%})"

        return False, None

    @staticmethod
    def analyze_advanced(
        neutral: ResponseInfo,
        true_injected: ResponseInfo,
        false_injected: ResponseInfo,
        engine: str = "generic",
    ) -> Tuple[bool, Optional[str]]:
        """Análisis avanzado boolean-based comparando variantes TRUE/FALSE.

        Args:
            neutral: Respuesta con payload neutral (sin condiciones booleanas)
            true_injected: Respuesta con payload TRUE
            false_injected: Respuesta con payload FALSE
            engine: Nombre del motor (solo para mensajes)

        Returns:
            Tupla (vulnerable, reason)
        """
        metrics_true = ResponseAnalyzer.compare_responses(neutral, true_injected)
        metrics_false = ResponseAnalyzer.compare_responses(neutral, false_injected)

        is_true_similar = ResponseAnalyzer.is_response_similar(neutral, true_injected)
        is_true_different = ResponseAnalyzer.is_response_different(neutral, true_injected)

        is_false_similar = ResponseAnalyzer.is_response_similar(neutral, false_injected)
        is_false_different = ResponseAnalyzer.is_response_different(neutral, false_injected)

        # Criterio 1: true similar y false diferente
        if is_true_similar and is_false_different:
            return True, f"boolean-based: TRUE similar, FALSE diferente; diff={metrics_true['len_diff_ratio']:.2f}"

        # Criterio 2: true diferente y false similar
        if is_true_different and is_false_similar:
            return True, f"boolean-based: TRUE diferente, FALSE similar; diff={metrics_false['len_diff_ratio']:.2f}"

        # Criterio 3: ambas diferentes pero en patrones coherentes
        if is_true_different and is_false_different:
            true_len = len(true_injected.body)
            false_len = len(false_injected.body)
            neutral_len = len(neutral.body)

            # Si una aumenta y otra disminuye, patrón coherente
            if (true_len > neutral_len and false_len < neutral_len) or (true_len < neutral_len and false_len > neutral_len):
                return True, f"boolean-based: patrones coherentes TRUE/FALSE"

        return False, None

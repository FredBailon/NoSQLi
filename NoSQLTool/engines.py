"""Estrategias especializadas de detección para diferentes motores NoSQL.

Este módulo define la interfaz base y las implementaciones específicas para
cada motor NoSQL (MongoDB, Neo4j, etc.). Cada estrategia encapsula:
- Generación de variantes booleanas (TRUE/FALSE)
- Generación de payloads neutros
- Análisis especializado si es necesario
"""

import json
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple

from .base_analysis import ResponseInfo, BooleanBasedAnalyzer, TimeBasedAnalyzer


class NoSQLEngineStrategy(ABC):
    """Interfaz base para estrategias especializadas de detección por motor NoSQL.
    
    Cada estrategia define cómo generar payloads modificados y cómo analizar
    respuestas para su motor específico.
    """

    @abstractmethod
    def generate_boolean_pair(self, payload: str) -> Tuple[Optional[str], Optional[str]]:
        """Genera variantes TRUE y FALSE de un payload.

        Args:
            payload: El payload original (puede ser JSON o string)

        Returns:
            Tupla (true_payload, false_payload) o (None, None) si no es posible
        """
        pass

    @abstractmethod
    def generate_neutral_payload(self, payload: str) -> str:
        """Genera una versión neutral/sin condiciones del payload.

        Args:
            payload: El payload original

        Returns:
            Payload neutro o "test" si no es posible crear uno
        """
        pass

    def analyze_error_based(self, baseline: ResponseInfo, injected: ResponseInfo) -> Tuple[bool, Optional[str]]:
        """Análisis de inyección basada en errores. Puede ser overrideado por subclases.
        
        Implementation por defecto: usa análisis genérico sin palabras clave específicas.
        
        Args:
            baseline: Respuesta sin inyección
            injected: Respuesta con payload inyectado
            
        Returns:
            Tupla (vulnerable, reason)
        """
        # Análisis genérico: cambios significativos en status code
        if baseline.status_code < 500 <= injected.status_code:
            return True, "error-based: 5xx nuevo en respuesta"

        if baseline.status_code != injected.status_code and baseline.status_code != 0:
            return True, "error-based: cambio de status code"

        return False, None

    def analyze_time_based(self, baseline: ResponseInfo, injected: ResponseInfo) -> Tuple[bool, Optional[str]]:
        """Análisis de inyección basada en tiempo. Usa TimeBasedAnalyzer por defecto."""
        return TimeBasedAnalyzer.analyze(baseline, injected)

    def analyze_boolean_based(
        self, baseline: ResponseInfo, injected: ResponseInfo, payload: str
    ) -> Tuple[bool, Optional[str]]:
        """Análisis básico de inyección boolean-based. Usa BooleanBasedAnalyzer por defecto."""
        return BooleanBasedAnalyzer.analyze_basic(baseline, injected, payload)

    def analyze_boolean_based_advanced(
        self, neutral: ResponseInfo, true_injected: ResponseInfo, false_injected: ResponseInfo
    ) -> Tuple[bool, Optional[str]]:
        """Análisis avanzado boolean-based. Usa BooleanBasedAnalyzer por defecto."""
        return BooleanBasedAnalyzer.analyze_advanced(neutral, true_injected, false_injected)


class MongoDBStrategy(NoSQLEngineStrategy):
    """Estrategia especializada para MongoDB."""

    def generate_boolean_pair(self, payload: str) -> Tuple[Optional[str], Optional[str]]:
        """Genera variantes TRUE/FALSE para MongoDB."""
        try:
            payload_dict = json.loads(payload)
            true_variant = self._boolean_variant(payload_dict, True)
            false_variant = self._boolean_variant(payload_dict, False)
            return (json.dumps(true_variant), json.dumps(false_variant))
        except (json.JSONDecodeError, TypeError):
            # Si no es JSON válido, intentar con strings
            return self._string_variant(payload)

    def generate_neutral_payload(self, payload: str) -> str:
        """Elimina condiciones booleanas en MongoDB."""
        try:
            payload_dict = json.loads(payload)
            neutral = self._neutral_variant(payload_dict)
            return json.dumps(neutral) if neutral else "test"
        except (json.JSONDecodeError, TypeError):
            pass

        # Fallback: intentar eliminar operadores booleanos comunes
        neutral = re.sub(r"(\s*&&\s*)?'1'\s*=\s*'1'", "", payload)
        neutral = re.sub(r"(\s*\|\|\s*)?'1'\s*=\s*'0'", "", neutral)
        neutral = re.sub(r"(\s*&&\s*)?1\s*==\s*1", "", neutral)
        neutral = re.sub(r"(\s*\|\|\s*)?1\s*==\s*0", "", neutral)

        return neutral.strip() if neutral.strip() else "test"

    @staticmethod
    def _boolean_variant(obj: Any, is_true: bool) -> Any:
        """Genera variante true/false para MongoDB."""
        if isinstance(obj, dict):
            result = obj.copy()

            for key, value in list(result.items()):
                if key == "$where":
                    expr = str(value)
                    if "==" in expr or "!=" in expr:
                        if is_true:
                            expr = re.sub(r"1==0", "1==1", expr)
                            expr = re.sub(r"'1'='0'", "'1'='1'", expr)
                        else:
                            expr = re.sub(r"1==1", "1==0", expr)
                            expr = re.sub(r"'1'='1'", "'1'='0'", expr)
                        result[key] = expr

                elif key == "$ne":
                    if is_true:
                        result["$eq"] = value
                        del result[key]
                    else:
                        result[key] = value

                elif key == "$gt":
                    if is_true:
                        result["$gt"] = value
                    else:
                        result["$lte"] = value
                        del result[key]

                elif key == "$lt":
                    if is_true:
                        result["$lt"] = value
                    else:
                        result["$gte"] = value
                        del result[key]

                elif isinstance(value, dict):
                    result[key] = MongoDBStrategy._boolean_variant(value, is_true)

            return result

        return obj

    @staticmethod
    def _string_variant(payload: str) -> Tuple[Optional[str], Optional[str]]:
        """Intenta generar variantes a partir de un payload string."""
        true_variant = payload.replace("1==0", "1==1").replace("'1'='0'", "'1'='1'")
        false_variant = payload.replace("1==1", "1==0").replace("'1'='1'", "'1'='0'")

        if true_variant != payload or false_variant != payload:
            return (true_variant, false_variant)

        return (None, None)

    @staticmethod
    def _neutral_variant(obj: Any) -> Optional[Any]:
        """Elimina condiciones booleanas en MongoDB."""
        if isinstance(obj, dict):
            result = {}

            for key, value in obj.items():
                if key in ("$where", "$expr"):
                    continue
                elif key in ("$ne", "$gt", "$lt", "$eq", "$gte", "$lte"):
                    continue
                elif isinstance(value, dict):
                    nested = MongoDBStrategy._neutral_variant(value)
                    if nested:
                        result[key] = nested
                else:
                    result[key] = value

            return result if result else None

        return None


class Neo4jStrategy(NoSQLEngineStrategy):
    """Estrategia especializada para Neo4j."""

    def generate_boolean_pair(self, payload: str) -> Tuple[Optional[str], Optional[str]]:
        """Genera variantes TRUE/FALSE para Neo4j (Cypher).
        
        Estrategia:
        1. Busca operadores de comparación: =, <>, !=, >, <, >=, <=
        2. Invierte el operador para crear FALSE variant
        3. Mantiene el operador para TRUE variant
        4. Si no hay operadores, intenta intercambiar true/false literales
        """
        true_variant = payload

        # 1) Prioridad: invertir una comparación existente del payload original.
        false_variant = self._invert_comparison(payload)
        if false_variant != payload and true_variant != false_variant:
            return (true_variant, false_variant)

        # 2) Fallback: invertir literales booleanos true/false.
        false_variant = self._swap_boolean_literals(payload)
        if false_variant != payload and true_variant != false_variant:
            return (true_variant, false_variant)

        # 3) Fallback: invertir predicados típicos de Cypher.
        false_variant = self._invert_cypher_predicate(payload)
        if false_variant != payload and true_variant != false_variant:
            return (true_variant, false_variant)

        # Si nada funcionó, retornar None.
        return (None, None)

    @staticmethod
    def _invert_comparison(payload: str) -> str:
        """Invierte dinámicamente la primera comparación del payload.

        Soporta operandos tipo:
        - Literales numéricos (1, 3.14)
        - Cadenas con comillas simples/dobles
        - Identificadores de Cypher (n.name)
        """
        # Mapeo de operadores y sus inversos para Cypher
        operator_map = {
            "=": "<>",
            "<>": "=",
            "!=": "=",
            ">": "<=",
            "<": ">=",
            ">=": "<",
            "<=": ">",
        }
        
        # 1) Priorizar comparaciones que aparecen dentro de contexto booleano (OR/AND).
        #    Este patrón es intencionalmente flexible para soportar payloads malformados
        #    pero comunes en pruebas (por ejemplo: "' or '1'='1").
        context_pattern = re.compile(
            r"(?i)(\b(?:or|and)\b\s+)(?P<left>[^\s()]+)\s*(?P<op>=|<>|!=|>=|<=|>|<)\s*(?P<right>[^\s()]+)"
        )

        match = context_pattern.search(payload)
        if match:
            operator = match.group("op")
            inverse = operator_map.get(operator)
            if inverse:
                return (
                    payload[: match.start("op")]
                    + inverse
                    + payload[match.end("op") :]
                )

        # 2) Comparaciones generales (incluye casos sin espacios como 1=1 o 'a'='a').
        comparison_pattern = re.compile(
            r"(?P<left>(?:'[^']*'|\"[^\"]*\"|[A-Za-z_][A-Za-z0-9_.]*|\d+(?:\.\d+)?))"
            r"\s*(?P<op>=|<>|!=|>=|<=|>|<)\s*"
            r"(?P<right>(?:'[^']*'|\"[^\"]*\"|[A-Za-z_][A-Za-z0-9_.]*|\d+(?:\.\d+)?))"
        )

        match = comparison_pattern.search(payload)
        if not match:
            return payload

        operator = match.group("op")
        inverse = operator_map.get(operator)
        if not inverse:
            return payload

        return (
            payload[: match.start("op")]
            + inverse
            + payload[match.end("op") :]
        )

    @staticmethod
    def _invert_cypher_predicate(payload: str) -> str:
        """Invierte predicados típicos de Cypher cuando no hay comparadores simples."""
        predicate_swaps = (
            (r"\bSTARTS\s+WITH\b", "NOT STARTS WITH"),
            (r"\bENDS\s+WITH\b", "NOT ENDS WITH"),
            (r"\bCONTAINS\b", "NOT CONTAINS"),
            (r"\bIS\s+NOT\s+NULL\b", "IS NULL"),
            (r"\bIS\s+NULL\b", "IS NOT NULL"),
        )

        for pattern, replacement in predicate_swaps:
            updated = re.sub(pattern, replacement, payload, count=1, flags=re.IGNORECASE)
            if updated != payload:
                return updated
        
        return payload

    @staticmethod
    def _swap_boolean_literals(payload: str) -> str:
        """Invierte el primer literal booleano encontrado (true <-> false)."""
        updated = re.sub(r"\btrue\b", "false", payload, count=1, flags=re.IGNORECASE)
        if updated != payload:
            return updated

        updated = re.sub(r"\bfalse\b", "true", payload, count=1, flags=re.IGNORECASE)
        return updated

    def generate_neutral_payload(self, payload: str) -> str:
        """Elimina/neutraliza condiciones booleanas en Neo4j."""
        neutral = payload
        
        # Reemplazar comparaciones booleanas con 1=1 (siempre verdadero)
        neutral = re.sub(r'\s*(=|<>|!=|>=|<=|>|<)\s*(?:true|false|"[^"]*"|\'[^\']*\'|\d+)', ' = 1', neutral)
        
        # Eliminar tokens booleanos sueltos
        neutral = re.sub(r'\s+(AND|OR|and|or)\s+(?:true|false)', '', neutral)
        neutral = re.sub(r'(?:true|false)\s+$', '', neutral)
        
        return neutral.strip() if neutral.strip() else "test"


def get_engine_strategy(engine: str) -> NoSQLEngineStrategy:
    """Obtiene la estrategia especializada para un motor NoSQL.

    Args:
        engine: Nombre del motor (mongodb, couchdb, neo4j, etc.)

    Returns:
        Instancia de NoSQLEngineStrategy específica del motor

    Raises:
        ValueError: Si el motor no es soportado
    """
    engine_lower = engine.lower()

    if "mongodb" in engine_lower or "mongo" in engine_lower:
        return MongoDBStrategy()

    elif "neo4j" in engine_lower:
        return Neo4jStrategy()

    # No incluimos CouchDB aquí, será importado desde couchdb_detection
    else:
        raise ValueError(f"Motor NoSQL no soportado: {engine}. Use un motor conocido o cree una estrategia personalizada.")
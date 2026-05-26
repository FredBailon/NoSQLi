import re
from typing import Optional, Tuple

from .engines import NoSQLEngineStrategy


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

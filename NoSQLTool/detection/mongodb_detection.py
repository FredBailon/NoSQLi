import json
import re
from typing import Any, Optional, Tuple

from .engines import NoSQLEngineStrategy


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

from typing import Dict

from ..payloads.resolver import normalize_engine
from .base import EngineProfile
from .couchdb import COUCHDB_PROFILE
from .mongo import MONGO_PROFILE
from .neo4j import NEO4J_PROFILE


ENGINE_PROFILES: Dict[str, EngineProfile] = {
    "mongo": MONGO_PROFILE,
    "neo4j": NEO4J_PROFILE,
    "couchdb": COUCHDB_PROFILE,
}


def get_engine_profile(engine: str) -> EngineProfile:
    canonical = normalize_engine(engine)
    return ENGINE_PROFILES[canonical]

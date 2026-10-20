"""Configuración central del prototipo, cargada desde el entorno (`.env`).

Un único punto de verdad para el proveedor de LLM, los hiperparámetros del
experimento y el disyuntor de tokens. Los hiperparámetros deben ser idénticos
en ambos brazos del estudio de ablación (multi-agente vs. agente único).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()


def _getenv_float(clave: str, defecto: float) -> float:
    valor = os.getenv(clave)
    return float(valor) if valor not in (None, "") else defecto


def _getenv_int(clave: str, defecto: int) -> int:
    valor = os.getenv(clave)
    return int(valor) if valor not in (None, "") else defecto


@dataclass(frozen=True)
class ConfigLLM:
    """Parámetros del modelo de lenguaje. Se aplican por igual a cada agente
    y al agente único baseline para garantizar la validez interna del
    experimento (numeral 1.6.3)."""

    proveedor: str = field(default_factory=lambda: os.getenv("LLM_PROVIDER", "anthropic").lower())
    modelo_anthropic: str = field(default_factory=lambda: os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6"))
    modelo_openai: str = field(default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o"))
    temperatura: float = field(default_factory=lambda: _getenv_float("LLM_TEMPERATURE", 0.2))
    top_p: float = field(default_factory=lambda: _getenv_float("LLM_TOP_P", 1.0))
    max_tokens: int = field(default_factory=lambda: _getenv_int("LLM_MAX_TOKENS", 4096))

    @property
    def modelo(self) -> str:
        return self.modelo_anthropic if self.proveedor == "anthropic" else self.modelo_openai


@dataclass(frozen=True)
class ConfigTokens:
    """Disyuntor de consumo de tokens (salvaguarda operativa, numeral 1.6.4).

    No es un KPI: es un control de seguridad que aborta corridas atrapadas en
    bucles de razonamiento antes de que contaminen las medias del experimento.
    """

    presupuesto_por_corrida: int = field(default_factory=lambda: _getenv_int("TOKEN_BUDGET_POR_CORRIDA", 200_000))
    presupuesto_por_agente: int = field(default_factory=lambda: _getenv_int("TOKEN_BUDGET_POR_AGENTE", 60_000))


@dataclass(frozen=True)
class Config:
    llm: ConfigLLM = field(default_factory=ConfigLLM)
    tokens: ConfigTokens = field(default_factory=ConfigTokens)
    nvd_api_key: str | None = field(default_factory=lambda: os.getenv("NVD_API_KEY") or None)
    phoenix_habilitado: bool = field(default_factory=lambda: os.getenv("PHOENIX_ENABLED", "false").lower() == "true")


@lru_cache(maxsize=1)
def get_config() -> Config:
    """Devuelve la configuración (memoizada) del proceso actual."""
    return Config()

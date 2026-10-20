"""Fábrica del modelo de lenguaje, agnóstica del proveedor.

`init_chat_model` de LangChain permite cambiar entre Anthropic (Claude Sonnet
4.6) y OpenAI (GPT-4o) con la misma interfaz. El proveedor y los
hiperparámetros se leen de la configuración central para que ambos brazos del
experimento usen exactamente los mismos parámetros.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .config import Config, get_config

if TYPE_CHECKING:  # pragma: no cover
    from langchain_core.language_models.chat_models import BaseChatModel


def crear_llm(config: Config | None = None) -> "BaseChatModel":
    """Instancia el chat model del proveedor configurado.

    La importación es diferida para que el resto del paquete (estado, modelos,
    grafo) se pueda importar y testear sin tener langchain instalado.
    """
    from langchain.chat_models import init_chat_model

    cfg = (config or get_config()).llm
    return init_chat_model(
        model=cfg.modelo,
        model_provider=cfg.proveedor,
        temperature=cfg.temperatura,
        max_tokens=cfg.max_tokens,
        model_kwargs={"top_p": cfg.top_p},
    )

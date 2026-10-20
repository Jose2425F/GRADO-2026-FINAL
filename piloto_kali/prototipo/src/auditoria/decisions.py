"""Contrato común: el LLM selecciona IDs y nunca aporta código ejecutable."""

from __future__ import annotations

import json
import re

PROMPT_VERSION = "scheduler-v4-v2-observations"


def decision_prompt(choices: list[str], context: dict, role: str) -> str:
    if not choices or any(
        not isinstance(choice, str)
        or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", choice) is None
        for choice in choices
    ) or len(set(choices)) != len(choices):
        raise ValueError("Se requieren identificadores autorizados únicos")
    return (
        "Eres un planificador de auditoría de laboratorio. El controlador ya autorizó "
        "las tareas y sus perfiles predefinidos. Elige exactamente un identificador de choices. "
        "No generes código, scripts, comandos, objetivos, credenciales ni instrucciones. "
        'Responde exclusivamente {"choice":"ID"}, sin campos adicionales.\n'
        + json.dumps(
            {"version": PROMPT_VERSION, "role": role, "choices": choices, "context": context},
            ensure_ascii=False,
            sort_keys=True,
        )
    )


def parse_choice(output: str, choices: list[str]) -> str:
    data = json.loads(output)
    if (
        not isinstance(data, dict)
        or set(data) != {"choice"}
        or not isinstance(data["choice"], str)
        or data["choice"] not in choices
    ):
        raise ValueError("choice_outside_authorized_set")
    return data["choice"]

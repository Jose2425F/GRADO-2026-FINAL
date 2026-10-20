"""Selección acotada de tareas; el transporte se implementa en OpenAIScheduler."""

from __future__ import annotations

from .contracts import Task, TaskResult
from .decisions import PROMPT_VERSION as PROMPT_VERSION


class Scheduler:
    """Núcleo de selección compartido; no configura ni llama a proveedores."""

    def __init__(self, *args, **kwargs):
        raise TypeError("Use OpenAIScheduler para planificar con la API de OpenAI")

    def decide(self, choices, context, role):
        raise NotImplementedError("El adaptador debe implementar la decisión autorizada")

    def select(self, ready: list[Task], previous: list[TaskResult], all_tasks: list[Task]) -> Task:
        if len(ready) == 1:
            return ready[0]
        task_map = {t.task_id: t for t in all_tasks}
        if not self.aliases:
            self.aliases = {t.task_id: f"t{i:03d}" for i, t in enumerate(all_tasks)}
            assets = list(dict.fromkeys(t.target.asset_id for t in all_tasks))
            self.asset_aliases = {a: f"a{i:03d}" for i, a in enumerate(assets)}

        def describe(task):
            return {
                "id": self.aliases[task.task_id],
                "role": task.agent_type,
                "profile": task.action_profile,
                "asset": self.asset_aliases[task.target.asset_id],
                "dependencies": [self.aliases[d] for d in task.dependencies],
            }

        def outcomes(role=None):
            return [
                {
                    "id": self.aliases[r.task_id],
                    "status": r.status,
                    "service_ports": [s.port for s in r.services],
                    "authentication": r.authentication.outcome if r.authentication else None,
                    "observations": {key: r.observations[key] for key in (
                        "restored", "access_observed", "state_changed", "control_received", "variant_udp_delivered"
                    ) if type(r.observations.get(key)) is bool},
                }
                for r in previous
                if role is None or task_map[r.task_id].agent_type == role
            ]

        if self.architecture == "single":
            choice = self.decide(
                [self.aliases[t.task_id] for t in ready],
                {"ready": [describe(t) for t in ready], "previous": outcomes()},
                "single_agent",
            )
        else:
            roles = list(dict.fromkeys(t.agent_type for t in ready))
            role = (
                self.decide(
                    roles,
                    {
                        "ready_counts": {r: sum(t.agent_type == r for t in ready) for r in roles},
                        "previous_statuses": [r.status for r in previous],
                    },
                    "administrator",
                )
                if len(roles) > 1
                else roles[0]
            )
            candidates = [t for t in ready if t.agent_type == role]
            choice = (
                self.decide(
                    [self.aliases[t.task_id] for t in candidates],
                    {"ready": [describe(t) for t in candidates], "previous": outcomes(role)},
                    role,
                )
                if len(candidates) > 1
                else self.aliases[candidates[0].task_id]
            )
        return next(t for t in ready if self.aliases[t.task_id] == choice)


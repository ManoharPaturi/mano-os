"""Trusted kernel ceilings; never part of a public action proposal."""

from dataclasses import dataclass

from .state import Denied


@dataclass(frozen=True)
class Limits:
    memory_bytes: int = 128 * 1024**2
    pids: int = 24
    cpu_percent: int = 20

    def body(self):
        return dict(memory_bytes=self.memory_bytes, pids=self.pids, cpu_percent=self.cpu_percent)

    @classmethod
    def parse(cls, value):
        ceilings = cls().body()
        if (not isinstance(value, dict) or set(value) != set(ceilings)
                or any(type(value[k]) is not int or not 1 <= value[k] <= maximum
                       for k, maximum in ceilings.items())):
            raise Denied("Invalid bounded kernel limits")
        return cls(**value)

    @classmethod
    def approved(cls, budget):
        ceilings = cls().body()
        if any(type(budget.get(k)) is not int or budget[k] <= 0 for k in ceilings):
            raise Denied("Invalid approved resource budget")
        return cls.parse({k: min(budget[k], maximum) for k, maximum in ceilings.items()})

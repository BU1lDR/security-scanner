"""Where scanners sign up so the engine can find them (contract §11, §16).

Each scanner class registers itself; the engine asks the registry which scanners
apply to a given target. A module-level default ``registry`` and the ``register``
decorator cover normal use; tests build their own :class:`Registry` instances to
stay isolated from global state.
"""

from __future__ import annotations

from scanner.core.scanner import Scanner
from scanner.core.target import Target


class Registry:
    def __init__(self) -> None:
        self._by_name: dict[str, type[Scanner]] = {}

    def register(self, cls: type[Scanner]) -> type[Scanner]:
        """Register a scanner class. Idempotent for the same class; raises if a
        different class tries to claim an already-used name. Returns the class so
        it can be used as a decorator."""
        existing = self._by_name.get(cls.name)
        if existing is not None and existing is not cls:
            raise ValueError(
                f"Scanner name {cls.name!r} is already registered to "
                f"{existing.__name__}; cannot also register {cls.__name__}."
            )
        self._by_name[cls.name] = cls
        return cls

    def get(self, name: str) -> type[Scanner]:
        return self._by_name[name]

    def names(self) -> list[str]:
        return sorted(self._by_name)

    def all(self) -> list[type[Scanner]]:
        return [self._by_name[name] for name in self.names()]

    def applicable(self, target: Target) -> list[type[Scanner]]:
        return [cls for cls in self.all() if cls.applicable(target)]


registry = Registry()
register = registry.register

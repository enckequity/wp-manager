"""Plugin settings (``config_schema`` in plugin.yaml), read through a swappable getter.

The agent side installs ``ctx.get_config``. Defaults apply when it is not available.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

DEFAULTS = {"op_binary": "op", "request_timeout": 60, "max_parallel": 4}

Getter = Callable[[str, Any], Any]
_getter: Getter = lambda key, default=None: default  # noqa: E731


def set_getter(getter: Getter | None) -> None:
    global _getter
    _getter = getter or (lambda key, default=None: default)


def _int(value: Any, default: int, low: int, high: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = default
    return max(low, min(high, n))


@dataclass(frozen=True)
class Settings:
    require_approval: bool = True
    op_binary: str = "op"
    request_timeout: int = 60
    max_parallel: int = 4

    @property
    def update_timeout(self) -> int:
        return max(300, self.request_timeout)


def current() -> Settings:
    def get(key: str) -> Any:
        try:
            return _getter(key, DEFAULTS[key])
        except Exception:
            return DEFAULTS[key]

    op_binary = str(get("op_binary") or "op").strip() or "op"
    return Settings(
        require_approval=True,  # pinned: approval cannot be configured off in the TeamShift build
        op_binary=op_binary,
        request_timeout=_int(get("request_timeout"), 60, 5, 600),
        max_parallel=_int(get("max_parallel"), 4, 1, 8),
    )

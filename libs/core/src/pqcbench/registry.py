
from __future__ import annotations
from typing import Dict, Any, Callable

class _Registry:
    def __init__(self) -> None:
        self._items: Dict[str, Any] = {}

    def register(self, name: str) -> Callable[[Any], Any]:
        def _inner(cls_or_obj: Any) -> Any:
            self._items[name] = cls_or_obj
            return cls_or_obj
        return _inner

    def get(self, name: str) -> Any:
        return self._items[name]

    def list(self) -> Dict[str, Any]:
        return dict(self._items)

registry = _Registry()

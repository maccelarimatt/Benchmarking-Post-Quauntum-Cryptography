from __future__ import annotations

import warnings

_available = False

try:
    from . import _core  # noqa: F401
except Exception as exc:  # pragma: no cover - best effort message
    warnings.warn(f"pqcbench_native disabled: {exc}")
else:
    from . import kem as _kem  # noqa: F401
    from . import sig as _sig  # noqa: F401
    if getattr(_core, "HAS_RSA", False):
        from . import rsa as _rsa  # noqa: F401
    _available = True

__all__ = ["_available"]

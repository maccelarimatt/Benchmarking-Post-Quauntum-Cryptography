"""Adapter package for liboqs-backed algorithms.

Importing submodules triggers registration of adapters (real or placeholders).
We don’t re-export class names to keep this resilient across fallback modes.
"""

# Trigger registration side-effects
from . import kem_adapters as _kem_adapters  # noqa: F401
from . import sig_adapters as _sig_adapters  # noqa: F401

__all__: list[str] = []

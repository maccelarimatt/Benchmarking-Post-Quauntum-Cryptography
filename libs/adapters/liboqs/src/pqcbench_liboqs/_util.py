from __future__ import annotations
import os
from typing import Iterable, Optional, Sequence


def try_import_oqs():
    try:
        import oqs  # type: ignore
        return oqs
    except Exception:
        return None


def resolve_algorithm(env_var: str, candidates: Sequence[str], enabled_syms: Iterable[str]) -> Optional[str]:
    """
    Choose an algorithm name for liboqs.
    - If env_var is set and present in enabled_syms, use it.
    - Otherwise, pick the first candidate contained in enabled_syms.
    Returns None if no match is found.
    """
    enabled = set(enabled_syms)
    val = os.getenv(env_var)
    if val and val in enabled:
        return val
    for c in candidates:
        if c in enabled:
            return c
    return None


def pick_kem_algorithm(oqs_mod, env_var: str, candidates: Sequence[str]) -> Optional[str]:
    """
    Robustly choose a KEM mechanism without relying on oqs helper lists,
    by attempting to instantiate each candidate. Honors env override first.
    """
    order: list[str] = []
    env_val = os.getenv(env_var)
    if env_val:
        order.append(env_val)
    order += [c for c in candidates if c != env_val]
    for name in order:
        try:
            with oqs_mod.KeyEncapsulation(name):
                return name
        except Exception:
            continue
    return None


def pick_sig_algorithm(oqs_mod, env_var: str, candidates: Sequence[str]) -> Optional[str]:
    """
    Robustly choose a SIG mechanism by attempting instantiation.
    """
    order: list[str] = []
    env_val = os.getenv(env_var)
    if env_val:
        order.append(env_val)
    order += [c for c in candidates if c != env_val]
    for name in order:
        try:
            with oqs_mod.Signature(name):
                return name
        except Exception:
            continue
    return None

def pick_stateful_sig_algorithm(oqs_mod, env_var: str, candidates: Sequence[str]) -> Optional[str]:
    """
    Choose a stateful signature mechanism (e.g., XMSS/XMSSMT) by attempting instantiation
    via oqs.StatefulSignature. Honors env override first.
    """
    order: list[str] = []
    env_val = os.getenv(env_var)
    if env_val:
        order.append(env_val)
    order += [c for c in candidates if c != env_val]
    for name in order:
        try:
            with oqs_mod.StatefulSignature(name):
                return name
        except Exception:
            continue
    return None

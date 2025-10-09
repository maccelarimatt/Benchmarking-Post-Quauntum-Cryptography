from __future__ import annotations
import os
from typing import Optional, Sequence


def try_import_oqs():
    try:
        import oqs  # type: ignore
        return oqs
    except Exception:
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

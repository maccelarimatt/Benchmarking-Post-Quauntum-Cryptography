
from __future__ import annotations
import time, json, pathlib
from dataclasses import dataclass, asdict
from typing import Callable, Dict, Any, List, Tuple
from pqcbench import registry

def _load_adapters() -> None:
    import importlib, traceback
    for mod in ("pqcbench_rsa", "pqcbench_liboqs"):
        try:
            importlib.import_module(mod)
        except Exception as e:
            print(f"[adapter import error] {mod}: {e}")
            traceback.print_exc()

_load_adapters()


@dataclass
class OpStats:
    runs: int
    mean_ms: float
    min_ms: float
    max_ms: float

@dataclass
class AlgoSummary:
    algo: str
    kind: str   # 'KEM' or 'SIG'
    ops: Dict[str, OpStats]
    meta: Dict[str, Any]

def measure(fn: Callable[[], None], runs: int) -> OpStats:
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        dt = (time.perf_counter() - t0) * 1000.0
        times.append(dt)
    mean = sum(times)/len(times)
    return OpStats(runs=runs, mean_ms=mean, min_ms=min(times), max_ms=max(times))

def export_json(summary: AlgoSummary, export_path: str | None) -> None:
    if not export_path:
        return
    # Normalize Windows-style separators on POSIX if users pass e.g. "results\file.json"
    if "\\" in export_path and ":" not in export_path:
        export_path = export_path.replace("\\", "/")
    path = pathlib.Path(export_path)
    # Resolve relative paths to the repository root so results/ always lands at repo root
    if not path.is_absolute():
        path = _repo_root() / path
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump({
            "algo": summary.algo,
            "kind": summary.kind,
            "ops": {k: asdict(v) for k,v in summary.ops.items()},
            "meta": summary.meta
        }, f, indent=2)

def _repo_root() -> pathlib.Path:
    """Best-effort detection of the repository root (directory containing .git).
    Falls back to the current working directory if not found.
    """
    here = pathlib.Path(__file__).resolve()
    for p in (here, *here.parents):
        if (p / ".git").exists():
            return p
    return pathlib.Path.cwd()

def run_kem(name: str, runs: int) -> AlgoSummary:
    cls = registry.get(name)
    ops = {}
    # measure keygen
    def do_keygen():
        _ = cls().keygen()
    ops["keygen"] = measure(do_keygen, runs)
    # For enc/dec we need fresh keys each time to be fair
    def do_encapsulate():
        pk, sk = cls().keygen()
        _ = cls().encapsulate(pk)
    ops["encapsulate"] = measure(do_encapsulate, runs)
    def do_decapsulate():
        pk, sk = cls().keygen()
        ct, ss = cls().encapsulate(pk)
        _ = cls().decapsulate(sk, ct)
    ops["decapsulate"] = measure(do_decapsulate, runs)
    # meta (sizes are placeholders if adapters are not real yet)
    pk, sk = cls().keygen()
    ct, ss = cls().encapsulate(pk)
    meta = {
        "public_key_len": len(pk) if isinstance(pk, (bytes, bytearray)) else None,
        "secret_key_len": len(sk) if isinstance(sk, (bytes, bytearray)) else None,
        "ciphertext_len": len(ct) if isinstance(ct, (bytes, bytearray)) else None,
        "shared_secret_len": len(ss) if isinstance(ss, (bytes, bytearray)) else None,
    }
    return AlgoSummary(algo=name, kind="KEM", ops=ops, meta=meta)

def run_sig(name: str, runs: int, message_size: int) -> AlgoSummary:
    cls = registry.get(name)
    ops = {}
    msg = b"x" * message_size
    def do_keygen():
        _ = cls().keygen()
    ops["keygen"] = measure(do_keygen, runs)
    def do_sign():
        pk, sk = cls().keygen()
        _ = cls().sign(sk, msg)
    ops["sign"] = measure(do_sign, runs)
    def do_verify():
        pk, sk = cls().keygen()
        sig = cls().sign(sk, msg)
        _ = cls().verify(pk, msg, sig)
    ops["verify"] = measure(do_verify, runs)
    pk, sk = cls().keygen()
    sig = cls().sign(sk, msg)
    meta = {
        "public_key_len": len(pk) if isinstance(pk, (bytes, bytearray)) else None,
        "secret_key_len": len(sk) if isinstance(sk, (bytes, bytearray)) else None,
        "signature_len": len(sig) if isinstance(sig, (bytes, bytearray)) else None,
        "message_size": message_size
    }
    return AlgoSummary(algo=name, kind="SIG", ops=ops, meta=meta)

from __future__ import annotations

import importlib
import sys
from collections import namedtuple
from dataclasses import dataclass, asdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

ROOT = Path(__file__).resolve().parents[2]
GUI_SRC = ROOT / "apps" / "gui" / "src"
if str(GUI_SRC) not in sys.path:
    sys.path.insert(0, str(GUI_SRC))


@dataclass
class DummyOpRow:
    runs: int
    mean_ms: float
    min_ms: float
    max_ms: float
    mem_mean_kb: float | None = None
    mem_min_kb: float | None = None
    mem_max_kb: float | None = None


class DummyKEM:
    def keygen(self):
        return b"pk" * 16, b"sk" * 16

    def encapsulate(self, pk):
        return b"ct" * 24, b"ss" * 16

    def decapsulate(self, sk, ct):
        return b"ss" * 16


class DummySignature:
    def keygen(self):
        return b"pk" * 12, b"sk" * 12

    def sign(self, sk, message):
        return b"sig" * 20

    def verify(self, pk, message, signature):
        return True


GuiTestEnv = namedtuple("GuiTestEnv", "client calls module")


@pytest.fixture
def gui_test_env(monkeypatch) -> GuiTestEnv:
    module_name = "webapp.app"
    if module_name in sys.modules:
        module = importlib.reload(sys.modules[module_name])
    else:
        module = importlib.import_module(module_name)

    module.app.config.update(TESTING=True)
    module.app.testing = True

    monkeypatch.setattr(module, "_ensure_adapters_loaded", lambda: None)

    original_items = dict(getattr(module.registry, "_items", {}))
    module.registry._items.clear()
    module.registry._items.update({
        "kyber": DummyKEM,
        "dilithium": DummySignature,
    })

    calls: Dict[str, List[Dict[str, Any]]] = {
        "run_kem": [],
        "run_sig": [],
        "export_json": [],
        "export_trace_kem": [],
        "export_trace_sig": [],
    }

    def make_summary(name: str, kind: str):
        ops_order = ["keygen", "encapsulate", "decapsulate"] if kind == "KEM" else ["keygen", "sign", "verify"]
        ops = {step: DummyOpRow(runs=3, mean_ms=0.12, min_ms=0.1, max_ms=0.2, mem_mean_kb=1.5, mem_min_kb=1.0, mem_max_kb=2.0) for step in ops_order}
        meta = {"runs": 3, "message_size": 512 if kind == "SIG" else 0, "algo": name}
        return SimpleNamespace(algo=name, kind=kind, ops=ops, meta=meta)

    original_run_kem = getattr(module, "run_kem", None)
    original_run_sig = getattr(module, "run_sig", None)
    original_export_json = getattr(module, "export_json", None)
    original_export_trace_kem = getattr(module, "export_trace_kem", None)
    original_export_trace_sig = getattr(module, "export_trace_sig", None)
    original_build_payload = getattr(module, "_build_export_payload", None)

    def fake_run_kem(name: str, runs: int):
        calls["run_kem"].append({"name": name, "runs": runs})
        return make_summary(name, "KEM")

    def fake_run_sig(name: str, runs: int, message_size: int):
        calls["run_sig"].append({"name": name, "runs": runs, "message_size": message_size})
        return make_summary(name, "SIG")

    def fake_export_json(summary, path: str, security_opts=None):
        calls["export_json"].append({"algo": summary.algo, "path": path, "security_opts": security_opts})

    def fake_export_trace_kem(name: str, path: str):
        calls["export_trace_kem"].append({"name": name, "path": path})

    def fake_export_trace_sig(name: str, message_size: int, path: str):
        calls["export_trace_sig"].append({"name": name, "message_size": message_size, "path": path})

    def fake_build_payload(summary, security_opts=None):
        return {
            "algo": summary.algo,
            "kind": summary.kind,
            "ops": {k: asdict(v) for k, v in summary.ops.items()},
            "meta": summary.meta,
            "security": security_opts or {"profile": "floor"},
        }

    module.run_kem = fake_run_kem
    module.run_sig = fake_run_sig
    module.export_json = fake_export_json
    module.export_trace_kem = fake_export_trace_kem
    module.export_trace_sig = fake_export_trace_sig
    module._build_export_payload = fake_build_payload

    client = module.app.test_client()

    try:
        yield GuiTestEnv(client=client, calls=calls, module=module)
    finally:
        module.registry._items.clear()
        module.registry._items.update(original_items)
        module.run_kem = original_run_kem
        module.run_sig = original_run_sig
        module.export_json = original_export_json
        module.export_trace_kem = original_export_trace_kem
        module.export_trace_sig = original_export_trace_sig
        module._build_export_payload = original_build_payload

from __future__ import annotations

import importlib
import sys
from collections import namedtuple
from dataclasses import dataclass, asdict
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Dict, List

import pytest

ROOT = Path(__file__).resolve().parents[2]
GUI_SRC = ROOT / "apps" / "gui" / "src"
if str(GUI_SRC) not in sys.path:
    sys.path.insert(0, str(GUI_SRC))

ENTROPY_SRC = GUI_SRC / "webapp"
if str(ENTROPY_SRC) not in sys.path:
    sys.path.insert(0, str(ENTROPY_SRC))


@dataclass
class DummyOpRow:
    runs: int
    mean_ms: float
    min_ms: float
    max_ms: float
    median_ms: float
    stddev_ms: float
    ci95_low_ms: float
    ci95_high_ms: float
    range_ms: float
    series: list[float]
    mem_mean_kb: float | None = None
    mem_min_kb: float | None = None
    mem_max_kb: float | None = None
    mem_median_kb: float | None = None
    mem_stddev_kb: float | None = None
    mem_ci95_low_kb: float | None = None
    mem_ci95_high_kb: float | None = None
    mem_range_kb: float | None = None
    mem_series_kb: list[float] | None = None
    runtime_scaling: Dict[str, Any] | None = None


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
    original_visual = sys.modules.get("pqc_visual")
    created_visual_stub = False
    original_entropy = sys.modules.get("entropy_tools")
    created_entropy_stub = False

    if original_visual is None:
        stub = ModuleType("pqc_visual")

        class PQCError(Exception):
            pass

        def _pair(prefix: str) -> tuple[bytes, bytes]:
            return (f"{prefix}-pk".encode("utf-8"), f"{prefix}-sk".encode("utf-8"))

        def _kem_encapsulate(mech, pk):
            return (b"ct-dummy", b"ss-dummy")

        def _kem_decapsulate(mech, sk, ct):
            return b"ss-dummy"

        def _sig_sign(mech, sk, message):
            return b"sig-dummy"

        def _sig_verify(mech, pk, message, signature):
            return True

        def _encrypt_image(payload):
            return {"ciphertext": "AAAA", "metadata": {"stub": True}}

        def _decrypt_image(payload):
            return {"plaintext": "AAAA", "metadata": {"stub": True}}

        stub.PQCError = PQCError
        stub.generate_kem_keypair = lambda mech: _pair("kem")
        stub.kem_encapsulate = _kem_encapsulate
        stub.kem_decapsulate = _kem_decapsulate
        stub.generate_sig_keypair = lambda mech: _pair("sig")
        stub.sig_sign = _sig_sign
        stub.sig_verify = _sig_verify
        stub.encrypt_image_payload = _encrypt_image
        stub.decrypt_image_payload = _decrypt_image

        sys.modules["pqc_visual"] = stub
        created_visual_stub = True

    try:
        import entropy_tools  # type: ignore  # noqa: F401
    except Exception:
        entropy_stub = ModuleType("entropy_tools")
        import base64 as _base64
        from types import SimpleNamespace as _SimpleNamespace

        class EntropyError(Exception):
            pass

        def _decode_buffer(b64_str: str) -> bytes:
            payload = b64_str.strip()
            if payload.startswith("data:"):
                _, _, payload = payload.partition(",")
            return _base64.b64decode(payload or "AA==")

        def _rgba_from_base64(b64_str: str):
            return [[0, 0, 0, 255]]

        def _rgba_bytes_to_array(data: bytes, width: int, height: int):
            return [[0, 0, 0, 255] for _ in range(max(1, width * height))]

        def _image_entropy_rgba(rgba, include_alpha=False, block=16):
            return _SimpleNamespace(
                width=1,
                height=1,
                bits_per_byte_global=0.0,
                bits_per_pixel_rgb=0.0,
                channel_bits={"R": 0.0, "G": 0.0, "B": 0.0},
                histograms={"R": [0], "G": [0], "B": [0]},
                block_entropy_rgb=[[0.0]],
                include_alpha=include_alpha,
                bits_per_pixel_rgba=0.0 if include_alpha else None,
            )

        def _summary_to_dict(summary):
            return {
                "width": getattr(summary, "width", 0),
                "height": getattr(summary, "height", 0),
                "bits_per_byte_global": getattr(summary, "bits_per_byte_global", 0.0),
                "bits_per_pixel_rgb": getattr(summary, "bits_per_pixel_rgb", 0.0),
                "channel_bits": getattr(summary, "channel_bits", {}),
                "histograms": getattr(summary, "histograms", {}),
                "block_entropy_rgb": getattr(summary, "block_entropy_rgb", []),
                "include_alpha": getattr(summary, "include_alpha", False),
                "bits_per_pixel_rgba": getattr(summary, "bits_per_pixel_rgba", None),
            }

        entropy_stub.PQCError = EntropyError
        entropy_stub.EntropySummary = _SimpleNamespace
        entropy_stub.decode_base64_buffer = _decode_buffer
        entropy_stub.rgba_from_base64 = _rgba_from_base64
        entropy_stub.rgba_bytes_to_array = _rgba_bytes_to_array
        entropy_stub.image_entropy_rgba = _image_entropy_rgba
        entropy_stub.summary_to_dict = _summary_to_dict

        sys.modules["entropy_tools"] = entropy_stub
        created_entropy_stub = True

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
        def _row():
            series = [0.12, 0.13, 0.11]
            mem_series = [1.5, 1.6, 1.4]
            return DummyOpRow(
                runs=len(series),
                mean_ms=sum(series) / len(series),
                min_ms=min(series),
                max_ms=max(series),
                median_ms=sorted(series)[len(series)//2],
                stddev_ms=0.0,
                ci95_low_ms=min(series),
                ci95_high_ms=max(series),
                range_ms=max(series) - min(series),
                series=series,
                mem_mean_kb=sum(mem_series) / len(mem_series),
                mem_min_kb=min(mem_series),
                mem_max_kb=max(mem_series),
                mem_median_kb=sorted(mem_series)[len(mem_series)//2],
                mem_stddev_kb=0.0,
                mem_ci95_low_kb=min(mem_series),
                mem_ci95_high_kb=max(mem_series),
                mem_range_kb=max(mem_series) - min(mem_series),
                mem_series_kb=mem_series,
                runtime_scaling=None,
            )
        ops = {step: _row() for step in ops_order}
        if kind == "KEM":
            meta = {
                "runs": 3,
                "algo": name,
                "backend": "liboqs",
                "mechanism": name.upper(),
                "public_key_len": 800,
                "secret_key_len": 1632,
                "ciphertext_len": 768,
                "shared_secret_len": 32,
                "run_mode": "warm",
                "security_level": {"applied_category": 3},
                "security_level_display": "Category 3 (≈ AES-192)",
            }
        else:
            meta = {
                "runs": 3,
                "message_size": 512,
                "algo": name,
                "backend": "liboqs",
                "mechanism": name.upper(),
                "public_key_len": 1472,
                "secret_key_len": 3500,
                "signature_len": 2701,
                "signature_expansion_ratio": 2701 / 512,
                "run_mode": "warm",
                "security_level": {"applied_category": 3},
                "security_level_display": "Category 3 (≈ AES-192)",
            }
        return SimpleNamespace(algo=name, kind=kind, ops=ops, meta=meta)

    original_run_kem = getattr(module, "run_kem", None)
    original_run_sig = getattr(module, "run_sig", None)
    original_export_json = getattr(module, "export_json", None)
    original_export_trace_kem = getattr(module, "export_trace_kem", None)
    original_export_trace_sig = getattr(module, "export_trace_sig", None)
    original_build_payload = getattr(module, "_build_export_payload", None)

    def fake_run_kem(name: str, runs: int, **kwargs):
        calls["run_kem"].append({"name": name, "runs": runs, **kwargs})
        return make_summary(name, "KEM")

    def fake_run_sig(name: str, runs: int, message_size: int, **kwargs):
        calls["run_sig"].append(
            {"name": name, "runs": runs, "message_size": message_size, **kwargs}
        )
        return make_summary(name, "SIG")

    def fake_export_json(summary, path: str, security_opts=None, **kwargs):
        calls["export_json"].append(
            {"algo": summary.algo, "path": path, "security_opts": security_opts, **kwargs}
        )

    def fake_export_trace_kem(name: str, path: str):
        calls["export_trace_kem"].append({"name": name, "path": path})

    def fake_export_trace_sig(name: str, message_size: int, path: str):
        calls["export_trace_sig"].append({"name": name, "message_size": message_size, "path": path})

    def fake_build_payload(summary, security_opts=None, **kwargs):
        return {
            "algo": summary.algo,
            "kind": summary.kind,
            "ops": {k: asdict(v) for k, v in summary.ops.items()},
            "meta": summary.meta,
            "security": security_opts or {"profile": "floor"},
            **({"validation": kwargs.get("validation")} if kwargs.get("validation") is not None else {}),
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
        if created_visual_stub:
            sys.modules.pop("pqc_visual", None)
        elif original_visual is not None:
            sys.modules["pqc_visual"] = original_visual
        if created_entropy_stub:
            sys.modules.pop("entropy_tools", None)
        elif original_entropy is not None:
            sys.modules["entropy_tools"] = original_entropy
        module.registry._items.clear()
        module.registry._items.update(original_items)
        module.run_kem = original_run_kem
        module.run_sig = original_run_sig
        module.export_json = original_export_json
        module.export_trace_kem = original_export_trace_kem
        module.export_trace_sig = original_export_trace_sig
        module._build_export_payload = original_build_payload

from __future__ import annotations

import builtins
import sys
import types
from pathlib import Path

import pytest
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]
CLI_SRC = ROOT / "apps" / "cli" / "src"
CORE_SRC = ROOT / "libs" / "core" / "src"

for candidate in (CLI_SRC, CORE_SRC):
    candidate_str = str(candidate)
    if candidate_str not in sys.path:
        sys.path.insert(0, candidate_str)

from pqcbench import registry  # noqa: E402
from pqcbench_cli import main as cli_main  # noqa: E402
from pqcbench_cli.runners import common as runners_common  # noqa: E402


class DummyKEMAdapter:
    def __init__(self) -> None:
        self._counter = 0

    def keygen(self) -> tuple[bytes, bytes]:
        tag = self._counter.to_bytes(2, "big", signed=False)
        self._counter += 1
        pk = b"pk" + tag
        sk = b"sk" + tag
        return pk, sk

    def encapsulate(self, pk: bytes) -> tuple[bytes, bytes]:
        suffix = pk[-2:]
        return b"ct" + suffix, b"ss" + suffix

    def decapsulate(self, sk: bytes, ct: bytes) -> bytes:
        return b"ss" + ct[-2:]


class DummySignatureAdapter:
    def __init__(self) -> None:
        self._counter = 0

    def keygen(self) -> tuple[bytes, bytes]:
        tag = self._counter.to_bytes(2, "big", signed=False)
        self._counter += 1
        pk = b"sgpk" + tag
        sk = b"sgsk" + tag
        return pk, sk

    def sign(self, sk: bytes, message: bytes) -> bytes:
        return b"sig" + sk[-2:] + len(message).to_bytes(2, "big", signed=False)

    def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
        return signature[-2:] == len(message).to_bytes(2, "big", signed=False)


@pytest.fixture(autouse=True)
def reduce_secret_sampling(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runners_common, "DEFAULT_SECRET_KEY_SAMPLES", 4)
    monkeypatch.setattr(runners_common, "DEFAULT_PAIR_SAMPLE_LIMIT", 4)


@pytest.fixture
def dummy_registry(monkeypatch: pytest.MonkeyPatch):
    original_items = dict(registry._items)  # type: ignore[attr-defined]
    registry._items.clear()  # type: ignore[attr-defined]
    registry._items.update(  # type: ignore[attr-defined]
        {
            "dummy-kem": DummyKEMAdapter,
            "dummy-sig": DummySignatureAdapter,
        }
    )
    runners_common.reset_adapter_cache()
    try:
        yield
    finally:
        registry._items.clear()  # type: ignore[attr-defined]
        registry._items.update(original_items)  # type: ignore[attr-defined]
        runners_common.reset_adapter_cache()


@pytest.fixture
def cli_runner() -> CliRunner:
    return CliRunner()


def test_cli_list_and_demo_commands(dummy_registry, cli_runner: CliRunner) -> None:
    result = cli_runner.invoke(cli_main.app, ["list-algos"])
    assert result.exit_code == 0
    assert "- dummy-kem" in result.output
    assert "- dummy-sig" in result.output

    kem_demo = cli_runner.invoke(cli_main.app, ["demo", "dummy-kem"])
    assert kem_demo.exit_code == 0
    assert "[KEM] dummy-kem: ok" in kem_demo.output

    sig_demo = cli_runner.invoke(cli_main.app, ["demo", "dummy-sig"])
    assert sig_demo.exit_code == 0
    assert "[SIG] dummy-sig: verify=True" in sig_demo.output


def test_run_kem_summary_structure(dummy_registry) -> None:
    summary = runners_common.run_kem(
        "dummy-kem",
        runs=2,
        cold=False,
        capture_memory=False,
    )
    assert summary.algo == "dummy-kem"
    assert summary.kind == "KEM"
    assert set(summary.ops) == {"keygen", "encapsulate", "decapsulate"}
    for stats in summary.ops.values():
        assert stats.runs == 2
        assert stats.mem_series_kb is None
    assert summary.meta["run_mode"] == "warm"
    assert summary.meta["backend"] == "unknown"
    assert summary.meta["ciphertext_len"] == 4
    assert summary.meta["shared_secret_len"] == 4
    analysis = summary.meta.get("secret_key_analysis")
    assert analysis is not None
    assert analysis["samples"] >= 4
    assert analysis["context"]["kind"] == "KEM"


def test_run_sig_summary_structure(dummy_registry) -> None:
    summary = runners_common.run_sig(
        "dummy-sig",
        runs=2,
        message_size=16,
        cold=False,
        capture_memory=False,
    )
    assert summary.algo == "dummy-sig"
    assert summary.kind == "SIG"
    assert set(summary.ops) == {"keygen", "sign", "verify"}
    for stats in summary.ops.values():
        assert stats.runs == 2
        assert stats.mem_series_kb is None
    assert summary.meta["run_mode"] == "warm"
    assert summary.meta["backend"] == "unknown"
    assert summary.meta["signature_len"] == 7
    assert summary.meta["signature_expansion_ratio"] == pytest.approx(7 / 16)
    analysis = summary.meta.get("secret_key_analysis")
    assert analysis is not None
    assert analysis["samples"] >= 4
    assert analysis["context"]["kind"] == "SIG"


def test_run_tests_cli_includes_all_targets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    liboqs_tests = tmp_path / "liboqs-python" / "tests"
    liboqs_tests.mkdir(parents=True)

    recorded: dict[str, object] = {}

    def fake_run(cmd, cwd=None, **kwargs):
        recorded["cmd"] = cmd
        recorded["cwd"] = Path(cwd) if cwd is not None else None
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(cli_main.subprocess, "run", fake_run)
    monkeypatch.setattr(cli_main.Path, "cwd", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(cli_main.sys, "executable", "PYTHON")
    monkeypatch.setitem(sys.modules, "oqs", types.ModuleType("oqs"))

    result = cli_runner.invoke(cli_main.app, ["run-tests"])
    assert result.exit_code == 0
    assert recorded["cmd"][:3] == ["PYTHON", "-m", "pytest"]  # type: ignore[index]
    assert str(tests_dir) in recorded["cmd"]  # type: ignore[operator]
    assert str(liboqs_tests) in recorded["cmd"]  # type: ignore[operator]
    assert recorded["cwd"] == tmp_path
    assert str(tests_dir) in result.output


def test_run_tests_cli_skip_option(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tmp_path / "liboqs-python" / "tests").mkdir(parents=True)

    recorded: dict[str, object] = {}

    def fake_run(cmd, cwd=None, **kwargs):
        recorded["cmd"] = cmd
        recorded["cwd"] = Path(cwd) if cwd is not None else None
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(cli_main.subprocess, "run", fake_run)
    monkeypatch.setattr(cli_main.Path, "cwd", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(cli_main.sys, "executable", "PYTHON")

    result = cli_runner.invoke(cli_main.app, ["run-tests", "--skip-liboqs"])
    assert result.exit_code == 0
    assert str(tests_dir) in recorded["cmd"]  # type: ignore[operator]
    assert all("liboqs-python" not in part for part in recorded["cmd"])  # type: ignore[operator]
    assert recorded["cwd"] == tmp_path


def test_run_tests_cli_missing_oqs_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cli_runner: CliRunner) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    liboqs_tests = tmp_path / "liboqs-python" / "tests"
    liboqs_tests.mkdir(parents=True)

    recorded: dict[str, object] = {}

    def fake_run(cmd, cwd=None, **kwargs):
        recorded["cmd"] = cmd
        recorded["cwd"] = Path(cwd) if cwd is not None else None
        return types.SimpleNamespace(returncode=5)

    monkeypatch.setattr(cli_main.subprocess, "run", fake_run)
    monkeypatch.setattr(cli_main.Path, "cwd", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(cli_main.sys, "executable", "PYTHON")
    monkeypatch.delitem(sys.modules, "oqs", raising=False)

    original_import = builtins.__import__

    def failing_import(name, *args, **kwargs):
        if name == "oqs":
            raise ModuleNotFoundError("no module named 'oqs'")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", failing_import)

    result = cli_runner.invoke(cli_main.app, ["run-tests"])
    assert result.exit_code == 5
    combined_output = result.output
    stderr_text = getattr(result, "stderr", "")
    if stderr_text:
        combined_output += stderr_text
    assert "Skipping liboqs-python tests because the `oqs` package is unavailable." in combined_output
    assert str(liboqs_tests) not in recorded["cmd"]  # type: ignore[operator]
    assert recorded["cwd"] == tmp_path

from __future__ import annotations

import base64
from urllib.parse import urlparse


def _post_single_run(client, **overrides):
    payload = {
        "algo": "kyber",
        "runs": "4",
        "message_size": "256",
        "do_export": "on",
        "export_path": "results/custom.json",
        "do_export_trace": "on",
        "export_trace_path": "results/custom_trace.json",
    }
    payload.update({k: str(v) for k, v in overrides.items()})
    return client.post("/run", data=payload)


def test_health_endpoint(gui_test_env):
    client = gui_test_env.client
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_index_lists_algorithms(gui_test_env):
    client = gui_test_env.client
    response = client.get("/")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Kyber" in body
    assert "Dilithium" in body
    assert 'name="runs"' in body


def test_index_shows_loading_overlay(gui_test_env):
    client = gui_test_env.client
    response = client.get("/")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'id="loading-overlay"' in body
    assert 'loading-spinner' in body


def test_run_kem_flow_shows_results_and_exports(gui_test_env):
    client = gui_test_env.client
    calls = gui_test_env.calls

    response = _post_single_run(client)

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Results" in body
    assert "Kyber" in body
    assert "custom.json" in body
    assert "Keygen" in body

    assert calls["run_kem"] and calls["run_kem"][0]["runs"] == 4
    assert calls["export_json"] and calls["export_json"][0]["path"].endswith("custom.json")
    assert calls["export_trace_kem"]


def test_run_kem_flow_includes_tables_and_charts(gui_test_env):
    client = gui_test_env.client
    response = _post_single_run(client)
    assert response.status_code == 200
    body = response.get_data(as_text=True)

    assert "Benchmark summary and charts" in body
    assert "Metadata" in body
    assert "Memory (peak RSS delta, KB)" in body
    assert 'id="charts"' in body
    assert 'id="mem-charts"' in body
    assert "Runs" in body
    assert "mean" in body.lower()
    assert "max" in body.lower()


def test_run_kem_flow_includes_json_and_trace_sections(gui_test_env):
    client = gui_test_env.client
    response = _post_single_run(client)
    assert response.status_code == 200
    body = response.get_data(as_text=True)

    expected_pk = base64.b64encode(b"pk" * 16).decode("ascii")
    expected_ct = base64.b64encode(b"ct" * 24).decode("ascii")
    expected_ss = base64.b64encode(b"ss" * 16).decode("ascii")

    assert "Open JSON summary export" in body
    assert "View raw data (one run)" in body
    assert "public_key" in body
    assert expected_pk in body
    assert "ciphertext" in body
    assert expected_ct in body
    assert "shared_secret" in body
    assert expected_ss in body


def test_execute_compare_pair_uses_signature_runner(gui_test_env):
    client = gui_test_env.client
    calls = gui_test_env.calls

    response = client.post(
        "/execute",
        data={
            "operation": "compare",
            "mode": "pair",
            "kind": "SIG",
            "algo_a": "kyber",
            "algo_b": "dilithium",
            "runs": "3",
            "message_size": "512",
        },
    )

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Compare Results" in body
    assert "Dilithium" in body
    assert "Runs:" in body
    assert "Algorithm" in body
    assert calls["run_sig"] and calls["run_sig"][0]["runs"] == 3
    assert calls["run_sig"][0]["message_size"] == 512


def test_compare_requires_selection_redirect(gui_test_env):
    client = gui_test_env.client

    response = client.post("/compare/run", data={"mode": "pair", "kind": "SIG"}, follow_redirects=False)

    assert response.status_code == 302
    location = response.headers.get("Location")
    assert location
    assert urlparse(location).path == "/"


def test_algo_detail_renders_template(gui_test_env):
    client = gui_test_env.client
    response = client.get("/algo/kyber")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Kyber" in body

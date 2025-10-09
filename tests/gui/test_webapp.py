from __future__ import annotations

import base64
from urllib.parse import urlparse

import pytest
from werkzeug.datastructures import MultiDict


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


def test_run_kem_flow_respects_cold_toggle(gui_test_env):
    client = gui_test_env.client
    calls = gui_test_env.calls

    response = _post_single_run(client, cold="on")

    assert response.status_code == 200
    assert calls["run_kem"], "run_kem should be invoked"
    assert calls["run_kem"][-1]["cold"] is True


def test_run_flow_collects_security_options(gui_test_env):
    client = gui_test_env.client
    calls = gui_test_env.calls

    response = _post_single_run(
        client,
        sec_adv="on",
        sec_rsa_phys="on",
        sec_profile="quantum",
        sec_phys_error_rate="0.001",
        sec_cycle_time_ns="500",
        sec_fail_prob="0.01",
        quantum_arch="iontrap-2025",
        rsa_model="ge2019",
        security_category="3",
        tests="on",
    )

    assert response.status_code == 200
    export_call = calls["export_json"][-1]
    opts = export_call["security_opts"]
    assert opts["lattice_use_estimator"] is True
    assert opts["rsa_surface"] is True
    assert opts["lattice_profile"] == "quantum"
    assert opts["quantum_arch"] == "iontrap-2025"
    assert opts["rsa_model"] == "ge2019"
    assert opts["phys_error_rate"] == pytest.approx(0.001)
    assert opts["cycle_time_s"] == pytest.approx(5e-7)
    assert opts["target_total_fail_prob"] == pytest.approx(0.01)


def test_run_sig_flow_renders_signature_table(gui_test_env):
    client = gui_test_env.client
    calls = gui_test_env.calls

    response = _post_single_run(client, algo="dilithium", message_size="512")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Sign" in body
    assert "Verify" in body
    assert calls["run_sig"], "run_sig should be invoked"
    sig_call = calls["run_sig"][-1]
    assert sig_call["name"] == "dilithium"
    assert sig_call["message_size"] == 512


def test_run_flow_unknown_algorithm_shows_error(gui_test_env):
    client = gui_test_env.client

    response = client.post("/run", data={"algo": "invalid", "runs": "1"})

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Unknown or unsupported algorithm" in body


def test_compare_via_checkboxes_uses_selected_algorithms(gui_test_env):
    client = gui_test_env.client
    calls = gui_test_env.calls

    form = MultiDict(
        [
            ("operation", "compare"),
            ("kind", "SIG"),
            ("algos", "dilithium"),
            ("runs", "2"),
            ("message_size", "256"),
        ]
    )
    response = client.post("/execute", data=form)

    assert response.status_code == 200
    assert calls["run_sig"], "run_sig should be called for compare selection"
    sig_call = calls["run_sig"][-1]
    assert sig_call["name"] == "dilithium"
    assert sig_call["runs"] == 2
    assert sig_call["message_size"] == 256


def test_api_kem_roundtrip(gui_test_env):
    client = gui_test_env.client

    keypair = client.post("/api/pqc/kem/keypair", json={"kem": "kyber"}).get_json()
    assert "publicKey" in keypair and "secretKey" in keypair

    encapsulated = client.post(
        "/api/pqc/kem/encapsulate",
        json={"kem": "kyber", "publicKey": keypair["publicKey"]},
    ).get_json()
    assert "ciphertext" in encapsulated and "sharedSecret" in encapsulated

    decapsulated = client.post(
        "/api/pqc/kem/decapsulate",
        json={
            "kem": "kyber",
            "secretKey": keypair["secretKey"],
            "ciphertext": encapsulated["ciphertext"],
        },
    ).get_json()
    assert decapsulated["sharedSecret"] == encapsulated["sharedSecret"]


def test_api_signature_roundtrip(gui_test_env):
    client = gui_test_env.client

    keypair = client.post("/api/pqc/sig/keypair", json={"sig": "dilithium"}).get_json()
    message = base64.b64encode(b"hello").decode("ascii")

    signature = client.post(
        "/api/pqc/sig/sign",
        json={
            "sig": "dilithium",
            "secretKey": keypair["secretKey"],
            "message": message,
        },
    ).get_json()
    assert "signature" in signature

    verify = client.post(
        "/api/pqc/sig/verify",
        json={
            "sig": "dilithium",
            "publicKey": keypair["publicKey"],
            "message": message,
            "signature": signature["signature"],
        },
    ).get_json()
    assert verify["ok"] is True


def test_api_entropy_requires_payload(gui_test_env):
    client = gui_test_env.client

    response = client.post("/api/pqc/entropy", json={})
    assert response.status_code == 400


def test_api_entropy_returns_summary(gui_test_env):
    client = gui_test_env.client

    response = client.post(
        "/api/pqc/entropy",
        json={
            "imageBytesBase64": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAOb6eioAAAAASUVORK5CYII=",
            "includeAlpha": True,
            "blockSize": 8,
        },
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["width"] == 1
    assert payload["height"] == 1


def test_api_analysis_returns_fallback(gui_test_env):
    client = gui_test_env.client

    response = client.post(
        "/api/analysis",
        json={
            "compare": {
                "kind": "KEM",
                "algos": [
                    {
                        "name": "kyber",
                        "label": "Kyber",
                        "ops": {
                            "keygen": {"mean_ms": 0.1},
                            "encapsulate": {"mean_ms": 0.2},
                            "decapsulate": {"mean_ms": 0.19},
                        },
                        "meta": {"public_key_len": 800},
                    }
                ],
            }
        },
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["used_fallback"] is True
    assert "automatic analysis" in data["analysis"].lower()


def test_api_encrypt_decrypt_image(gui_test_env):
    client = gui_test_env.client

    encrypted = client.post("/api/pqc/encrypt-image", json={"payload": "stub"})
    assert encrypted.status_code == 200
    enc_payload = encrypted.get_json()
    assert enc_payload["ciphertext"] == "AAAA"

    decrypted = client.post("/api/pqc/decrypt-image", json={"payload": "stub"})
    assert decrypted.status_code == 200
    dec_payload = decrypted.get_json()
    assert dec_payload["plaintext"] == "AAAA"

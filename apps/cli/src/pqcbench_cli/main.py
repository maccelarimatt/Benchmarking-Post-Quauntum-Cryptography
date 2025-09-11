
from __future__ import annotations
import typer
from pqcbench import registry
from .runners.common import _load_adapters

app = typer.Typer(add_completion=False, help="PQC Investigation CLI")

@app.command()
def list_algos():
    """List registered algorithms available via adapters."""
    _load_adapters()
    for name in registry.list().keys():
        typer.echo(f"- {name}")

@app.command()
def demo(name: str):
    """Run a tiny demo with the selected algorithm (keygen + one op)."""
    _load_adapters()
    algo_cls = registry.get(name)
    algo = algo_cls()
    if hasattr(algo, "keygen"):
        pk, sk = algo.keygen()
        if hasattr(algo, "encapsulate"):
            ct, ss = algo.encapsulate(pk)
            _ = algo.decapsulate(sk, ct)
            typer.echo(f"[KEM] {name}: ok (placeholder)")
        else:
            sig = algo.sign(sk, b"hello")
            ok = algo.verify(pk, b"hello", sig)
            typer.echo(f"[SIG] {name}: verify={ok} (placeholder)")
    else:
        typer.echo("Algorithm missing keygen")

def app_main():
    app()

if __name__ == "__main__":
    app_main()

# Extra diagnostic command: list oqs mechanisms by probing
@app.command(name="probe-oqs")
def probe_oqs() -> None:
    """Probe common OQS KEM/SIG mechanisms supported by your install."""
    try:
        import oqs  # type: ignore
    except Exception as e:
        typer.echo(f"oqs import failed: {e}")
        raise typer.Exit(code=1)
    kem_candidates = [
        "ML-KEM-768", "ML-KEM-1024", "Kyber512", "Kyber768", "Kyber1024",
        "HQC-128", "HQC-192", "HQC-256", "HQC-128-1-CCA2", "HQC-192-1-CCA2", "HQC-256-1-CCA2",
    ]
    sig_candidates = [
        "ML-DSA-65", "ML-DSA-87", "ML-DSA-110", "Dilithium2", "Dilithium3", "Dilithium5",
        "Falcon-512", "Falcon-1024",
        "SPHINCS+-SHA2-128f-simple", "SPHINCS+-SHA2-128s-simple", "SPHINCS+-SHAKE-128f-simple",
        "MAYO-1", "MAYO-2", "MAYO-3", "MAYO-5",
    ]
    st_sig_candidates = [
        "XMSSMT-SHA2_20/2_256", "XMSSMT-SHA2_20/4_256", "XMSS-SHA2_20_256",
    ]
    found_kem = []
    for name in kem_candidates:
        try:
            with oqs.KeyEncapsulation(name):
                found_kem.append(name)
        except Exception:
            pass
    found_sig = []
    for name in sig_candidates:
        try:
            with oqs.Signature(name):
                found_sig.append(name)
        except Exception:
            pass
    found_st_sig = []
    for name in st_sig_candidates:
        try:
            with oqs.StatefulSignature(name):
                found_st_sig.append(name)
        except Exception:
            pass
    typer.echo("KEM mechanisms:")
    for n in found_kem:
        typer.echo(f"- {n}")
    typer.echo("SIG mechanisms:")
    for n in found_sig:
        typer.echo(f"- {n}")
    typer.echo("Stateful SIG mechanisms:")
    for n in found_st_sig:
        typer.echo(f"- {n}")

# Backwards-compatible alias with underscore name (zsh/bash examples)
app.command(name="probe_oqs")(probe_oqs)

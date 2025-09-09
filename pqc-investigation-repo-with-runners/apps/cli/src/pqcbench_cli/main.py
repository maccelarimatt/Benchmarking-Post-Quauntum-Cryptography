
from __future__ import annotations
import typer
from pqcbench import registry

app = typer.Typer(add_completion=False, help="PQC Investigation CLI")

@app.command()
def list_algos():
    """List registered algorithms available via adapters."""
    for name in registry.list().keys():
        typer.echo(f"- {name}")

@app.command()
def demo(name: str):
    """Run a tiny demo with the selected algorithm (keygen + one op)."""
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

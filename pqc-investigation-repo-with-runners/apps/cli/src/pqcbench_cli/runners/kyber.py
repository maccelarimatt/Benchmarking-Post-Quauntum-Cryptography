
from __future__ import annotations
import typer, json
from .common import run_kem, export_json

app = typer.Typer(add_completion=False)

@app.command()
def main(runs: int = 10, export: str = "results/kyber_summary.json", print_json: bool = True):
    """
    Run kyber KEM micro-bench (keygen/encapsulate/decapsulate).
    """
    summary = run_kem("kyber", runs)
    export_json(summary, export)
    if print_json:
        import json
        typer.echo(json.dumps({
            "algo": summary.algo,
            "kind": summary.kind,
            "ops": {k: vars(v) for k,v in summary.ops.items()},
            "meta": summary.meta
        }, indent=2))

def app_main():
    app()

if __name__ == "__main__":
    app_main()

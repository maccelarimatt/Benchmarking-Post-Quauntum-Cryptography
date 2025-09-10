
from __future__ import annotations
import typer, json
from .common import run_sig, export_json, export_trace_sig

app = typer.Typer(add_completion=False)

@app.command()
def main(
    runs: int = 10,
    message_size: int = 1024,
    export: str = "results/rsa_pss_summary.json",
    export_raw: str = "",
    print_json: bool = True,
):
    """
    Run rsa_pss signature micro-bench (keygen/sign/verify).
    """
    summary = run_sig("rsa-pss", runs, message_size)
    export_json(summary, export)
    if export_raw:
        export_trace_sig("rsa-pss", message_size, export_raw)
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


from __future__ import annotations
import typer, json
from .common import run_sig, export_json, export_trace_sig
from .common import _build_export_payload

app = typer.Typer(add_completion=False)

@app.command()
def main(
    runs: int = 10,
    message_size: int = 1024,
    cold: bool = typer.Option(True, help="Cold starts: isolate each run in a fresh process (use --no-cold for warm, cache-friendly runs)"),
    export: str = "results/sphincsplus_summary.json",
    export_raw: str = "",
    print_json: bool = True,
    # Security estimator flags
    sec_adv: bool = typer.Option(False, help="Enable advanced lattice estimator when available"),
    sec_rsa_phys: bool = typer.Option(False, help="Include surface-code physical overhead (RSA only)"),
    sec_phys_error_rate: float = typer.Option(1e-3, help="Physical error rate per operation"),
    sec_cycle_time_ns: float = typer.Option(1000.0, help="Surface code cycle time (ns)"),
    sec_fail_prob: float = typer.Option(1e-2, help="Target total failure probability for the run"),
):
    """
    Run sphincsplus signature micro-bench (keygen/sign/verify).
    """
    summary = run_sig("sphincs+", runs, message_size, cold=cold)
    _opts = {
        "lattice_use_estimator": bool(sec_adv),
        "rsa_surface": bool(sec_rsa_phys),
        "phys_error_rate": float(sec_phys_error_rate),
        "cycle_time_s": float(sec_cycle_time_ns) * 1e-9,
        "target_total_fail_prob": float(sec_fail_prob),
    }
    export_json(summary, export, security_opts=_opts)
    if export_raw:
        export_trace_sig("sphincs+", message_size, export_raw)
    if print_json:
        import json
        typer.echo(json.dumps(_build_export_payload(summary, security_opts=_opts), indent=2))

def app_main():
    app()

if __name__ == "__main__":
    app_main()

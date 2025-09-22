
from __future__ import annotations
import typer, json
from .common import run_sig, export_json, export_trace_sig
from .common import _build_export_payload, run_acvp_validation

app = typer.Typer(add_completion=False)

@app.command()
def main(
    runs: int = 10,
    message_size: int = 1024,
    cold: bool = typer.Option(True, help="Cold starts: isolate each run in a fresh process (use --no-cold for warm, cache-friendly runs)"),
    export: str = "results/falcon_summary.json",
    export_raw: str = "",
    print_json: bool = True,
    tests: bool = typer.Option(False, help="Run ACVP functional validation when available"),
    # Security estimator flags
    sec_adv: bool = typer.Option(False, help="Enable advanced lattice estimator when available"),
    sec_rsa_phys: bool = typer.Option(False, help="Include surface-code physical overhead (RSA only)"),
    sec_phys_error_rate: float = typer.Option(1e-3, help="Physical error rate per operation"),
    sec_cycle_time_ns: float = typer.Option(1000.0, help="Surface code cycle time (ns)"),
    sec_fail_prob: float = typer.Option(1e-2, help="Target total failure probability for the run"),
    sec_profile: str = typer.Option("floor", help="Security profile: floor|classical|quantum"),
    quantum_arch: str = typer.Option("", help="Quantum arch preset: superconducting-2025|iontrap-2025"),
):
    """
    Run falcon signature micro-bench (keygen/sign/verify).
    """
    summary = run_sig("falcon", runs, message_size, cold=cold)
    validation = None
    validation_logs: list[str] = []
    if tests:
        validation, validation_logs = run_acvp_validation(summary)
        for line in validation_logs:
            typer.echo(line)
    _opts = {
        "lattice_use_estimator": bool(sec_adv),
        "lattice_profile": sec_profile,
        "rsa_surface": bool(sec_rsa_phys),
        "phys_error_rate": float(sec_phys_error_rate),
        "cycle_time_s": float(sec_cycle_time_ns) * 1e-9,
        "target_total_fail_prob": float(sec_fail_prob),
        "quantum_arch": quantum_arch or None,
    }
    export_json(summary, export, security_opts=_opts, validation=validation)
    if export_raw:
        export_trace_sig("falcon", message_size, export_raw)
    if print_json:
        typer.echo(
            json.dumps(
                _build_export_payload(summary, security_opts=_opts, validation=validation),
                indent=2,
            )
        )

def app_main():
    app()

if __name__ == "__main__":
    app_main()

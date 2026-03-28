import typer
from reconforge.core.runner import run_scan
from reconforge.models.target import validate_target

app = typer.Typer(help="ReconForge CLI")


@app.callback()
def main():
    """
    ReconForge command line interface.
    """
    pass


@app.command()
def run(
    target: str,
    output_dir: str = typer.Option("output", "--output-dir", help="Directory to save reports."),
    wordlist: str = typer.Option(None, "--wordlist", help="Path to subdomain wordlist"),
):
    """
    Run reconnaissance against a target.
    """
    try:
        validated_target = validate_target(target)
    except ValueError as exc:
        typer.echo(f"[-] {exc}")
        raise typer.Exit(code=1)

    run_scan(validated_target, output_dir, wordlist)

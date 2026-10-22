from rich.console import Console

console = Console()

def banner():
    console.print("[bold cyan]toolkit[/bold cyan] [dim]— offensive toolkit [/dim]")
    console.print()

def info(msg: str):
    console.print(f"[cyan][*][/cyan] {msg}")


def success(msg: str):
    console.print(f"[green][+][/green] {msg}")


def warn(msg: str):
    console.print(f"[yellow][!][/yellow] {msg}")


def error(msg: str):
    console.print(f"[red][-][/red] {msg}")
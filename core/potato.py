"""
Potato banner for the toolkit.

Because every good offensive tool needs a mascot.
"""

from rich.console import Console
from rich.panel import Panel

console = Console()


POTATO_ART = r"""
                    .-~~~-.
          .- ~ ~-(       )_ _
         /                     ~ -.
        |                P O T A T O \
         \                         .'
           ~- . _____________ . -~
"""


POTATO_ART_LARGE = r"""
                    .-~~~-.
          .- ~ ~-(       )_ _
         /                     ~ -.
        |                            \
        |         P  O  T  A  T  O     |
         \                           .'
           ~- . _________________ . -~
              (___________________)
"""


def print_potato_banner(version="0.1", module_counts=None):
    """Print the toolkit banner with a potato mascot."""
    lines = [POTATO_ART.strip("\n")]
    lines.append("")
    lines.append(f"[bold cyan]toolkit[/bold cyan] v{version}  "
                 f"[dim]— the potato edition[/dim]")
    lines.append("")

    if module_counts:
        lines.append(f"+ -- --=[ {module_counts.get('recon', 0):4d} recon modules    ]")
        lines.append(f"+ -- --=[ {module_counts.get('vuln', 0):4d} vuln modules     ]")
        lines.append(f"+ -- --=[ {module_counts.get('payload', 0):4d} payload modules  ]")

    console.print(Panel(
        "\n".join(lines),
        border_style="yellow",
        title="[bold yellow]tk[/bold yellow]",
        subtitle="[dim]stay starchy[/dim]",
    ))
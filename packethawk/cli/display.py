from rich.console import Console
from rich.table   import Table
from rich.panel   import Panel
from rich         import box
from datetime     import datetime
import pyfiglet

console = Console()

SEVERITY_COLOURS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold red",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold green",
    "INFO":     "bold blue",
}

SEVERITY_ICONS = {
    "CRITICAL": "!!",
    "HIGH":     "! ",
    "MEDIUM":   "~ ",
    "LOW":      ". ",
    "INFO":     "i ",
}

def print_banner():
    console.print()
    ascii_art = pyfiglet.figlet_format("PacketHawk", font="big")
    console.print(f"[bold cyan]{ascii_art}[/bold cyan]", end="")
    console.print(
        "  [bold white]Network Packet Analyser & Anomaly Detector[/bold white]  "
        "[dim]| v1.0.0[/dim]\n"
        "  [dim]Built for Blue Team security analysis[/dim]\n"
    )
    console.print(
        f"  [dim]Started:[/dim] "
        f"[white]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/white]"
        f"  [dim]|[/dim]  "
        f"[dim]Author:[/dim] [white]Veer564[/white]\n"
    )
    console.rule("[dim cyan]─[/dim cyan]")
    console.print()

def print_alerts(alerts):
    if not alerts:
        console.print(Panel(
            "[bold green]No anomalies detected. Network looks clean.[/bold green]",
            border_style="green",
            padding=(0, 2),
        ))
        return

    critical = [a for a in alerts if a.get("severity") == "CRITICAL"]
    high     = [a for a in alerts if a.get("severity") == "HIGH"]
    medium   = [a for a in alerts if a.get("severity") == "MEDIUM"]
    low      = [a for a in alerts if a.get("severity") == "LOW"]

    table = Table(
        title="PacketHawk — Detected Anomalies",
        box=box.ROUNDED,
        show_lines=True,
        title_style="bold cyan",
        header_style="bold white",
    )

    table.add_column("",            width=3)
    table.add_column("Severity",    style="bold",    width=10)
    table.add_column("Rule",        style="cyan",    width=16)
    table.add_column("Description", style="white",   width=45)
    table.add_column("Source IP",   style="magenta", width=18)
    table.add_column("Time",        style="dim",     width=18)

    for alert in alerts:
        severity = alert.get("severity", "LOW")
        colour   = SEVERITY_COLOURS.get(severity, "white")
        icon     = SEVERITY_ICONS.get(severity, "  ")
        table.add_row(
            f"[{colour}]{icon}[/{colour}]",
            f"[{colour}]{severity}[/{colour}]",
            alert.get("rule_name",   "—"),
            alert.get("description", "—"),
            alert.get("src_ip")     or "—",
            alert.get("timestamp")  or "—",
        )

    console.print(table)
    console.print()

    summary = (
        f"[bold red]{len(critical)} CRITICAL[/bold red]  "
        f"[bold red]{len(high)} HIGH[/bold red]  "
        f"[bold yellow]{len(medium)} MEDIUM[/bold yellow]  "
        f"[bold green]{len(low)} LOW[/bold green]"
    )
    console.print(Panel(
        f"[bold white]{len(alerts)} anomaly(s) detected[/bold white]   {summary}",
        border_style="red" if (critical or high) else "yellow",
        padding=(0, 2),
    ))
    console.print()

def print_stats(stats):
    console.print()
    table = Table(
        title="PacketHawk — Database Stats",
        box=box.SIMPLE,
        title_style="bold cyan",
        header_style="bold white",
        show_header=False,
    )
    table.add_column("Metric", style="dim",        width=25)
    table.add_column("Value",  style="bold white", width=15)

    table.add_row("Total packets captured", str(stats.get("packets",  0)))
    table.add_row("Total alerts fired",     str(stats.get("alerts",   0)))
    table.add_row("Critical alerts",        str(stats.get("critical", 0)))
    table.add_row("High alerts",            str(stats.get("high",     0)))
    table.add_row("Medium alerts",          str(stats.get("medium",   0)))
    table.add_row("Unique source IPs",      str(stats.get("src_ips",  0)))
    table.add_row("Unique destination IPs", str(stats.get("dst_ips",  0)))

    console.print(table)
    console.print()

def print_packet_summary(packets):
    from collections import Counter
    if not packets:
        console.print("[dim]No packets to summarise.[/dim]")
        return

    protocols = Counter(p.protocol for p in packets)
    top_src   = Counter(p.src_ip   for p in packets).most_common(5)
    top_ports = Counter(
        p.dst_port for p in packets if p.dst_port
    ).most_common(5)

    console.print()
    console.rule("[cyan]Packet Summary[/cyan]")

    proto_table = Table(box=box.SIMPLE, show_header=True,
                        header_style="bold white")
    proto_table.add_column("Protocol", style="cyan",       width=12)
    proto_table.add_column("Count",    style="bold white", width=10)
    for proto, count in protocols.most_common():
        proto_table.add_row(proto, str(count))
    console.print(proto_table)

    src_table = Table(box=box.SIMPLE, show_header=True,
                      header_style="bold white")
    src_table.add_column("Top Source IPs", style="magenta",   width=20)
    src_table.add_column("Packets",        style="bold white", width=10)
    for ip, count in top_src:
        src_table.add_row(ip, str(count))
    console.print(src_table)

    port_table = Table(box=box.SIMPLE, show_header=True,
                       header_style="bold white")
    port_table.add_column("Top Dest Ports", style="yellow",    width=20)
    port_table.add_column("Hits",           style="bold white", width=10)
    for port, count in top_ports:
        port_table.add_row(str(port), str(count))
    console.print(port_table)
    console.print()
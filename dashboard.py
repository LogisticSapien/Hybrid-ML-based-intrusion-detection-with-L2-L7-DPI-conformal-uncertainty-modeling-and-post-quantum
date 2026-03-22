"""
Rich Terminal Dashboard
========================
Real-time terminal UI powered by the Rich library:
  • Live packet feed with color-coded protocols
  • Statistics panels (bandwidth, packets, uptime)
  • Threat alert bar with severity coloring
  • Top talkers display
  • Active TCP flows table
  • PQC encryption status
  • Protocol distribution breakdown
"""

from __future__ import annotations

import time
from collections import deque
from typing import TYPE_CHECKING, List, Optional

from rich.console import Console, Group
from rich.columns import Columns
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from analytics import AnalyticsManager, BandwidthMonitor
    from ids import IDSEngine, ThreatEvent, Severity
    from pqc import PQCSecureLogger, QuantumThreatAnalyzer


# ──────────────────────────────────────────────────────────────────────
# Color scheme
# ──────────────────────────────────────────────────────────────────────

PROTO_COLORS = {
    "TCP":   "cyan",
    "UDP":   "green",
    "DNS":   "yellow",
    "HTTP":  "bright_blue",
    "TLS":   "magenta",
    "QUIC":  "bright_magenta",
    "ICMP":  "bright_red",
    "ARP":   "bright_yellow",
    "SSH":   "bright_green",
    "DHCP":  "bright_cyan",
    "IPv6":  "blue",
}

SEVERITY_COLORS = {
    1: "white",          # INFO
    2: "yellow",         # LOW
    3: "dark_orange",    # MEDIUM
    4: "red",            # HIGH
    5: "bold red",       # CRITICAL
}

SEVERITY_ICONS = {
    1: "ℹ️ ",
    2: "🟡",
    3: "🟠",
    4: "🔴",
    5: "🚨",
}


# ──────────────────────────────────────────────────────────────────────
# Packet Feed
# ──────────────────────────────────────────────────────────────────────

class PacketFeed:
    """Ring buffer of formatted packet lines for the live feed."""

    def __init__(self, max_lines: int = 25):
        self.lines: deque = deque(maxlen=max_lines)

    def add(self, protocol: str, summary: str, extra: Optional[str] = None):
        color = PROTO_COLORS.get(protocol, "white")
        ts = time.strftime("%H:%M:%S")
        line = Text()
        line.append(f"[{ts}] ", style="dim")
        line.append(f"[{protocol:5s}] ", style=f"bold {color}")
        line.append(summary, style=color)
        if extra:
            line.append(f"  {extra}", style="dim italic")
        self.lines.append(line)

    def render(self) -> Panel:
        if not self.lines:
            content = Text("Waiting for packets...", style="dim italic")
        else:
            content = Group(*self.lines)
        return Panel(
            content,
            title="[bold bright_white]📡 Live Packet Feed[/]",
            border_style="bright_blue",
            padding=(0, 1),
        )


# ──────────────────────────────────────────────────────────────────────
# Dashboard Renderer
# ──────────────────────────────────────────────────────────────────────

class Dashboard:
    """Main dashboard coordinator — renders all panels into a Rich Layout."""

    def __init__(
        self,
        analytics: 'AnalyticsManager',
        ids_engine: 'IDSEngine',
        pqc_logger: Optional['PQCSecureLogger'] = None,
        qt_analyzer: Optional['QuantumThreatAnalyzer'] = None,
    ):
        self.analytics = analytics
        self.ids = ids_engine
        self.pqc_logger = pqc_logger
        self.qt_analyzer = qt_analyzer
        self.feed = PacketFeed(max_lines=22)
        self.console = Console()
        self._live: Optional[Live] = None

    def start(self):
        """Start the live display."""
        self._live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=2,
            screen=True,
        )
        self._live.start()

    def stop(self):
        """Stop the live display."""
        if self._live:
            self._live.stop()

    def update(self):
        """Refresh the dashboard."""
        if self._live:
            self._live.update(self._render())

    def _render(self) -> Layout:
        """Build the full dashboard layout."""
        layout = Layout()

        # Header
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )

        layout["header"].update(self._render_header())
        layout["footer"].update(self._render_footer())

        # Body: left (feed + alerts) | right (stats + flows)
        layout["body"].split_row(
            Layout(name="left", ratio=3),
            Layout(name="right", ratio=2),
        )

        layout["left"].split_column(
            Layout(name="feed", ratio=3),
            Layout(name="alerts", ratio=1),
        )
        layout["feed"].update(self.feed.render())
        layout["alerts"].update(self._render_alerts())

        layout["right"].split_column(
            Layout(name="stats", size=12),
            Layout(name="protos", size=10),
            Layout(name="flows"),
        )
        layout["stats"].update(self._render_stats())
        layout["protos"].update(self._render_protocols())
        layout["flows"].update(self._render_flows())

        return layout

    def _render_header(self) -> Panel:
        title = Text()
        title.append("  ⚛️  QUANTUM SNIFFER  ", style="bold bright_white on dark_blue")
        title.append("  Post-Quantum Protected Network Analyzer  ", style="italic bright_cyan")
        uptime = self.analytics.uptime
        h, r = divmod(int(uptime), 3600)
        m, s = divmod(r, 60)
        title.append(f"  ⏱ {h:02d}:{m:02d}:{s:02d}", style="bright_green")
        return Panel(title, style="bright_blue", padding=0)

    def _render_footer(self) -> Panel:
        footer = Text()
        footer.append(" Ctrl+C to stop ", style="bold")
        footer.append(" │ ", style="dim")

        if self.pqc_logger:
            s = self.pqc_logger.stats
            footer.append(f"🔐 PQC: {s['entries_logged']} entries, ", style="bright_green")
            footer.append(f"chain={'✅' if s['chain_intact'] else '❌'}, ", style="bright_green" if s["chain_intact"] else "red")
            footer.append(f"rotations={s['key_rotations']}", style="bright_green")
        else:
            footer.append("🔓 PQC: disabled", style="dim")

        footer.append(" │ ", style="dim")

        if self.qt_analyzer:
            vs = self.qt_analyzer.vulnerability_summary
            footer.append(
                f"🛡️ Quantum: {vs['quantum_safe']}✅ {vs['quantum_vulnerable']}⚠️",
                style="bright_yellow"
            )

        return Panel(footer, style="dim", padding=0)

    def _render_stats(self) -> Panel:
        bw = self.analytics.bandwidth
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Stat", style="bold bright_white", width=20)
        table.add_column("Value", style="bright_cyan")

        table.add_row("Total Packets", f"{bw.total_packets:,}")
        table.add_row("Total Bytes", bw.format_bytes(bw.total_bytes))
        table.add_row("Bandwidth", f"{bw.format_bytes(bw.bytes_per_second)}/s")
        table.add_row("Packet Rate", f"{bw.packets_per_second:.1f} pkt/s")
        table.add_row("Active Flows", str(len(self.analytics.flows.active_flows)))
        table.add_row("Threats", f"{self.ids.stats['threats_detected']}")
        table.add_row("DNS Queries", str(len(self.analytics.dns_queries)))
        table.add_row("TLS SNIs", str(len(self.analytics.tls_snis)))

        return Panel(
            table,
            title="[bold bright_white]📊 Statistics[/]",
            border_style="bright_green",
        )

    def _render_protocols(self) -> Panel:
        top = self.analytics.protocols.top_protocols
        if not top:
            return Panel(
                Text("No data yet", style="dim"),
                title="[bold]Protocol Distribution[/]",
                border_style="bright_yellow",
            )

        total = sum(c for _, c in top)
        table = Table(show_header=True, box=None, padding=(0, 1))
        table.add_column("Proto", style="bold", width=8)
        table.add_column("Count", justify="right", width=8)
        table.add_column("%", justify="right", width=6)
        table.add_column("Bar", width=20)

        for proto, count in top[:7]:
            pct = (count / total) * 100 if total else 0
            color = PROTO_COLORS.get(proto, "white")
            bar_len = int(pct / 5)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            table.add_row(
                Text(proto, style=f"bold {color}"),
                str(count),
                f"{pct:.1f}",
                Text(bar, style=color),
            )

        return Panel(
            table,
            title="[bold bright_white]📶 Protocols[/]",
            border_style="bright_yellow",
        )

    def _render_flows(self) -> Panel:
        flows = self.analytics.flows.active_flows[:8]
        if not flows:
            return Panel(
                Text("No active flows", style="dim"),
                title="[bold]Active Flows[/]",
                border_style="bright_magenta",
            )

        table = Table(show_header=True, box=None, padding=(0, 0))
        table.add_column("Flow", style="cyan", no_wrap=True, max_width=35)
        table.add_column("State", style="bold", width=12)
        table.add_column("Pkts", justify="right", width=6)
        table.add_column("SNI", style="dim", max_width=20)

        state_colors = {
            "ESTABLISHED": "green",
            "SYN_SENT": "yellow",
            "SYN_RECEIVED": "yellow",
            "FIN_WAIT": "red",
            "CLOSED": "dim",
            "RESET": "red",
        }

        for f in flows:
            state_color = state_colors.get(f.state.value, "white")
            key = f"{f.src_ip}:{f.src_port}→{f.dst_ip}:{f.dst_port}"
            if len(key) > 35:
                key = key[:32] + "..."
            table.add_row(
                key,
                Text(f.state.value, style=state_color),
                str(f.packets),
                f.sni or "",
            )

        return Panel(
            table,
            title="[bold bright_white]🔗 Active TCP Flows[/]",
            border_style="bright_magenta",
        )

    def _render_alerts(self) -> Panel:
        recent = self.ids.get_recent_alerts(8)
        if not recent:
            return Panel(
                Text("  No threats detected ✅", style="bright_green"),
                title="[bold bright_white]🛡️ Threat Alerts[/]",
                border_style="green",
            )

        lines = []
        for alert in reversed(recent):
            line = Text()
            icon = SEVERITY_ICONS.get(alert.severity, "•")
            color = SEVERITY_COLORS.get(alert.severity, "white")
            ts = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
            line.append(f" {icon} [{ts}] ", style="dim")
            line.append(f"[{alert.category}] ", style=f"bold {color}")
            desc = alert.description
            if len(desc) > 70:
                desc = desc[:67] + "..."
            line.append(desc, style=color)
            lines.append(line)

        return Panel(
            Group(*lines),
            title="[bold bright_white]🛡️ Threat Alerts[/]",
            border_style="red" if any(a.severity >= 4 for a in recent) else "yellow",
        )


# ──────────────────────────────────────────────────────────────────────
# Simple print-mode fallback (no Rich)
# ──────────────────────────────────────────────────────────────────────

class SimplePrinter:
    """Fallback for --no-dashboard mode."""

    def __init__(self):
        self.packet_count = 0

    def print_packet(self, protocol: str, summary: str, extra: Optional[str] = None):
        self.packet_count += 1
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] [{protocol:5s}] {summary}"
        if extra:
            line += f"  ({extra})"
        print(line)

    def print_alert(self, alert: 'ThreatEvent'):
        ts = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
        sev = SEVERITY_ICONS.get(alert.severity, "•")
        print(f"  {sev} ALERT [{ts}] [{alert.category}] {alert.description}")
        if alert.mitre_ref:
            print(f"      MITRE: {alert.mitre_ref}")

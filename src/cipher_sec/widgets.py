"""Cipher-Sec project widgets — engagement gate + safety monitor.

The EngagementGate is a sidebar tab that ALWAYS shows the current
engagement, scope authorization status, and a persistent safety-monitor
stripe. Out-of-scope targets are visually fenced (red banner). When the
sabotage-detection classifier crosses a threshold, the stripe pins red
and the chat composer is gated until the user acknowledges.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Literal

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widget import Widget
from textual.widgets import Static


SafetyState = Literal["ok", "watch", "blocked"]


@dataclass
class Engagement:
    id: str = "ENG-DEFAULT"
    name: str = "(no engagement loaded)"
    rules_of_engagement: str = ""
    in_scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    expires_at: str = ""


@dataclass
class Finding:
    id: str
    severity: Literal["info", "low", "med", "high", "critical"]
    title: str
    target: str
    cve: str = ""


_DEMO_ENGAGEMENT = Engagement(
    id="ENG-2026-Q2-15",
    name="Acme Corp — internal pentest, scope C",
    rules_of_engagement="Confirmed by procurement 2026-04-22; HITL gate on every exploit step.",
    in_scope=[
        "*.staging.acme.local",
        "10.42.0.0/16",
        "vpn-bastion.acme.local",
    ],
    out_of_scope=[
        "*.prod.acme.local",
        "*.customer.acme.com",
        "any external infra",
    ],
    expires_at="2026-06-30 23:59 UTC",
)


_DEMO_FINDINGS = [
    Finding(id="F-3201", severity="critical", title="auth bypass via JWT alg=none",
            target="api.staging.acme.local", cve="CWE-345"),
    Finding(id="F-3199", severity="high", title="SSRF in webhook receiver",
            target="hooks.staging.acme.local", cve="CWE-918"),
    Finding(id="F-3187", severity="med",  title="weak ECC curve",
            target="vpn-bastion.acme.local"),
]


_SEV_STYLE = {
    "info": "blue",
    "low": "cyan",
    "med": "yellow",
    "high": "orange3",
    "critical": "red",
}


class EngagementGate(Vertical):
    DEFAULT_CSS = """
    EngagementGate {
        height: 1fr;
    }
    EngagementGate #safety {
        height: 3;
        padding: 0 1;
        background: $bg_alt;
    }
    EngagementGate #scope {
        height: 1fr;
        padding: 0 1;
        background: $bg;
    }
    EngagementGate #findings {
        height: 1fr;
        padding: 0 1;
        background: $bg_alt;
    }
    """

    def __init__(self, engagement: Engagement | None = None,
                 findings: List[Finding] | None = None,
                 safety: SafetyState = "ok") -> None:
        super().__init__()
        self.engagement = engagement or _DEMO_ENGAGEMENT
        self.findings = findings if findings is not None else list(_DEMO_FINDINGS)
        self.safety = safety

    def compose(self) -> ComposeResult:
        yield Static(self._render_safety(), id="safety")
        yield Static(self._render_scope(), id="scope")
        yield Static(self._render_findings(), id="findings")

    def _render_safety(self) -> RenderableType:
        styles = {
            "ok":      ("●", "green",  "safety: OK · sabotage classifier within bounds"),
            "watch":   ("◍", "yellow", "safety: WATCH · 1 anomaly in last 5 calls"),
            "blocked": ("✗", "red",    "safety: BLOCKED · HITL acknowledgment required"),
        }
        glyph, color, msg = styles[self.safety]
        head = Text()
        head.append(f"{glyph}  ", style=f"bold {color}")
        head.append(msg, style=color)
        head.append("\n")
        head.append(self.engagement.id, style="bold")
        head.append("  ·  ", style="dim")
        head.append(self.engagement.name, style="default")
        head.append("\n")
        head.append(f"expires: {self.engagement.expires_at}", style="dim")
        return head

    def _render_scope(self) -> RenderableType:
        body = Text()
        body.append("in-scope\n", style="bold green")
        for s in self.engagement.in_scope or ["(none)"]:
            body.append(f"  ✓ {s}\n", style="green")
        body.append("\nout-of-scope\n", style="bold red")
        for s in self.engagement.out_of_scope or ["(none)"]:
            body.append(f"  ✗ {s}\n", style="red")
        return Panel(body, title="[bold]scope[/]", title_align="left",
                     border_style="cyan")

    def _render_findings(self) -> RenderableType:
        if not self.findings:
            return Panel(Text("(no findings yet)", style="dim"),
                         title="[bold]findings[/]", title_align="left",
                         border_style="dim")
        table = Table(show_header=True, header_style="bold cyan", box=None,
                      padding=(0, 1), expand=True)
        table.add_column("id", no_wrap=True, style="bold")
        table.add_column("sev", no_wrap=True)
        table.add_column("target", no_wrap=True, style="magenta")
        table.add_column("title", overflow="fold")
        for f in self.findings:
            sev_color = _SEV_STYLE.get(f.severity, "white")
            table.add_row(
                f.id,
                Text(f.severity.upper(), style=sev_color),
                f.target,
                f.title,
            )
        return Panel(table, title="[bold]findings[/]", title_align="left",
                     border_style="cyan")

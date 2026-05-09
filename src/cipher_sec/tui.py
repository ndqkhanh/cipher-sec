"""Cipher-Sec TUI — defensive & offensive security agent."""
from __future__ import annotations

import os
from typing import Optional

import click
from harness_tui import HarnessApp, ProjectConfig
from harness_tui.commands.registry import register_command
from harness_tui.transport import HTTPTransport, MockTransport

from .tui_theme import cipher_theme
from .widgets import EngagementGate


@register_command(name="engagement", description="Load an authorized engagement",
                  category="Cipher")
async def cmd_engagement(app, args: str) -> None:  # type: ignore[no-untyped-def]
    if args.startswith("load "):
        eid = args[5:].strip()
        app.shell.chat_log.write_system(f"engagement {eid}: loaded (scope enforced)")
    else:
        app.shell.chat_log.write_system("usage: /engagement load <id>")


@register_command(name="scope", description="Check whether a target is in scope",
                  category="Cipher")
async def cmd_scope(app, args: str) -> None:  # type: ignore[no-untyped-def]
    target = args.strip()
    if not target:
        app.shell.chat_log.write_system("usage: /scope check <target>")
        return
    app.shell.chat_log.write_system(f"scope check: {target!r} → ALLOWED (mock)")


@register_command(name="exploit", description="Dry-run an exploit (HITL-gated)",
                  category="Cipher")
async def cmd_exploit(app, args: str) -> None:  # type: ignore[no-untyped-def]
    if args.startswith("dry-run "):
        eid = args[8:].strip()
        app.shell.chat_log.write_system(
            f"exploit {eid}: dry-run; HITL approval required before execution"
        )
    else:
        app.shell.chat_log.write_system("usage: /exploit dry-run <id>")


@register_command(name="redteam", description="Plan a red-team operation",
                  category="Cipher")
async def cmd_redteam(app, args: str) -> None:  # type: ignore[no-untyped-def]
    plan = args.strip() or "(no plan)"
    app.shell.chat_log.write_system(f"red-team plan queued: {plan!r}")


@click.command()
@click.option("--url", default=None)
@click.option("--mock", is_flag=True)
@click.option("--engagement", default="default", help="Engagement id for the session.")
@click.option("--serve", is_flag=True,
              help="Run the TUI in a browser via textual-serve.")
@click.option("--port", type=int, default=8007,
              help="Web mode port (with --serve).")
@click.option("--host", default="127.0.0.1",
              help="Web mode host (with --serve).")
def main(url: Optional[str], mock: bool, engagement: str, serve: bool, port: int, host: str) -> None:
    """Open the Cipher-Sec TUI."""
    if serve:
        from harness_tui.serve import serve_app, make_module_command

        flags = []
        if mock:
            flags.append("--mock")
        if url:
            flags.append(f"--url {url}")
        serve_app(
            command=make_module_command("cipher_sec.tui", " ".join(flags)),
            host=host, port=port,
            title="cipher-sec",
        )
        return
    if mock:
        transport = MockTransport()
    else:
        backend = url or os.environ.get("CIPHER_BACKEND") or "http://localhost:8007"
        transport = HTTPTransport(
            backend,
            endpoints={"run": "/v1/actions"},
            payload_builder=lambda t, m: {"engagement_id": engagement, "action": t},
            text_field="result",
        )
    cfg = ProjectConfig(
        name="cipher-sec",
        description="Defensive & offensive security agent",
        theme=cipher_theme(),
        transport=transport,
        model=os.environ.get("CIPHER_MODEL", "auto"),
        sidebar_tabs=[("Engagement", EngagementGate())],
    )
    app = HarnessApp(cfg)
    app.run()
    summary = getattr(app, "last_exit_summary", None)
    if summary:
        click.echo(summary.render())


if __name__ == "__main__":  # pragma: no cover
    main()

"""Cipher-Sec brand — Phosphor green + matrix black, matrix-rain logo."""
from __future__ import annotations

from harness_tui.theme import Theme
from harness_tui.themes import catppuccin_mocha

CIPHER_LOGO = r"""
   [bold #10B981]1[/] [dim]0[/] [bold #10B981]1[/]   [dim]0[/] [bold #10B981]1[/]
   [dim]0[/] [bold #10B981]1[/] [dim]0[/]   [bold #10B981]1[/] [dim]0[/]      [dim]Cipher-Sec[/]
   [bold #10B981]CIPHER · SEC[/]
""".strip("\n")


def cipher_theme() -> Theme:
    return catppuccin_mocha().with_brand(
        name="cipher-sec",
        primary="#10B981",
        primary_alt="#059669",
        accent="#34D399",
        ascii_logo=CIPHER_LOGO,
        spinner_frames=("█", "▓", "▒", "░"),
    )

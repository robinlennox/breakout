#!/usr/bin/env python3
"""ASCII banner and terminal colour helpers for Breakout."""

import sys
from typing import Tuple


def banner() -> None:
    """Print the Breakout ASCII art banner."""
    G, Y, B, R, W = colour()

    art = (
        R
        + r"""
                 ____                 _               _
                |  _ \               | |             | |
                | |_) |_ __ ___  __ _| | _____  _   _| |_
                |  _ <| '__/ _ \/ _` | |/ / _ \| | | | __|
                | |_) | | |  __/ (_| |   < (_) | |_| | |_
                |____/|_|  \___|\__,_|_|\_\___/ \__,_|\__|"""
        + W + Y
        + "\n                # Coded By Robin Lennox\n"
    )
    print(art)


def colour() -> Tuple[str, str, str, str, str]:
    """Return (Green, Yellow, Blue, Red, White/reset) ANSI escape strings."""
    if sys.platform.startswith("win"):
        return ("", "", "", "", "")

    return (
        "\033[92m",  # green
        "\033[93m",  # yellow
        "\033[94m",  # blue
        "\033[91m",  # red
        "\033[0m",   # reset
    )

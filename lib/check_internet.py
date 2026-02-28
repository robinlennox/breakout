#!/usr/bin/env python3
"""Simple internet connectivity check for Breakout."""

import requests


def check_internet(timeout: int = 1) -> bool:
    """Return *True* if the host can reach the internet."""
    try:
        requests.get("https://www.google.com", timeout=timeout)
        return True
    except requests.RequestException:
        return False

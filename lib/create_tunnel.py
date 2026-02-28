#!/usr/bin/env python3
"""Backward compatibility re-exports for the split CreateTunnel module."""

from lib.tunnel import (
    initialise_tunnel,
    callback_tcp,
    callback_non_tcp,
    check_ports,
    quick_scan,
)
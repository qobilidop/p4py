"""STF test runner for BMv2.

Parses STF (Simple Test Framework) files, compiles P4 programs, runs them
on BMv2 simple_switch, and verifies packet outputs.
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


# ---------------------------------------------------------------------------
# STF parsing
# ---------------------------------------------------------------------------


def parse_stf_string(text: str) -> list[tuple[str, str]]:
    """Parse STF text into a list of (command, args) tuples."""
    commands = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        commands.append((parts[0].lower(), parts[1] if len(parts) > 1 else ""))
    return commands


def parse_stf(path: str) -> list[tuple[str, str]]:
    """Parse an STF file into a list of (command, args) tuples."""
    with open(path) as f:
        return parse_stf_string(f.read())


# ---------------------------------------------------------------------------
# Hex matching
# ---------------------------------------------------------------------------


def match_hex(actual: str, expected: str) -> bool:
    """Compare two hex strings. '*' in expected matches any nibble."""
    actual = actual.lower()
    expected = expected.lower()
    if len(actual) != len(expected):
        return False
    return all(e == "*" or a == e for a, e in zip(actual, expected))

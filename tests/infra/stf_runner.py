"""STF parsing and simulator translation.

Parses STF (Simple Test Framework) files and translates them into
inputs for the P4Py simulator.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

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


# ---------------------------------------------------------------------------
# STF to simulator translation
# ---------------------------------------------------------------------------


@dataclass
class SimPacket:
    """A packet to send to the simulator."""

    port: int
    data: bytes


@dataclass
class SimExpect:
    """An expected output packet."""

    port: int
    pattern: str | None


@dataclass
class SimInputs:
    """Parsed STF translated to simulator inputs."""

    table_entries: dict[str, list[dict]]
    packets: list[SimPacket]
    expects: list[SimExpect]


def stf_to_sim_inputs(stf_text: str) -> SimInputs:
    """Translate STF text into simulator inputs.

    Strips control-block prefixes (e.g. 'MyIngress.') from table and
    action names so the result matches the simulator's naming convention.
    """
    commands = parse_stf_string(stf_text)

    table_entries: dict[str, list[dict]] = {}
    packets: list[SimPacket] = []
    expects: list[SimExpect] = []

    for cmd, args in commands:
        if cmd == "add":
            _parse_stf_add_to_sim(args, table_entries)
        elif cmd == "packet":
            parts = args.split(None, 1)
            port = int(parts[0])
            hex_data = parts[1].replace(" ", "") if len(parts) > 1 else ""
            packets.append(SimPacket(port=port, data=bytes.fromhex(hex_data)))
        elif cmd == "expect":
            parts = args.split(None, 1)
            port = int(parts[0])
            pattern = (
                parts[1].replace(" ", "").rstrip("$").lower()
                if len(parts) > 1
                else None
            )
            expects.append(SimExpect(port=port, pattern=pattern))

    return SimInputs(table_entries=table_entries, packets=packets, expects=expects)


def _strip_control_prefix(name: str) -> str:
    """Strip a dotted control-block prefix: 'MyIngress.foo' -> 'foo'."""
    return name.rsplit(".", 1)[-1]


def _parse_stf_add_to_sim(args: str, table_entries: dict[str, list[dict]]) -> None:
    """Parse an STF 'add' command into simulator table_entries format."""
    # p4testgen wraps identifiers in quotes; strip them.
    tokens = args.replace('"', "").split()
    table = _strip_control_prefix(tokens[0])

    action_token = ""
    key_pairs: list[tuple[str, str]] = []
    in_action = False

    for token in tokens[1:]:
        if "(" in token and not in_action:
            action_token = token
            if ")" in token:
                in_action = False
            else:
                in_action = True
        elif in_action:
            action_token += " " + token
            if ")" in token:
                in_action = False
        elif ":" in token:
            field, value = token.split(":", 1)
            key_pairs.append((field, value))

    # Parse action name and parameters.
    action_name = _strip_control_prefix(action_token[: action_token.index("(")])
    params_str = action_token[action_token.index("(") + 1 : action_token.rindex(")")]
    action_args: dict[str, int] = {}
    if params_str.strip():
        for param in params_str.split(","):
            name, value = param.strip().split(":", 1)
            action_args[name.strip()] = int(value.strip(), 0)

    # Build key dict, extracting LPM prefix lengths.
    key_dict: dict[str, int] = {}
    prefix_len_dict: dict[str, int] = {}
    for field, value in key_pairs:
        if "/" in value:
            val_str, plen_str = value.rsplit("/", 1)
            key_dict[field] = int(val_str.replace("*", "0"), 0)
            prefix_len_dict[field] = int(plen_str)
        else:
            key_dict[field] = int(value.replace("*", "0"), 0)

    entry: dict = {"key": key_dict, "action": action_name, "args": action_args}
    if prefix_len_dict:
        entry["prefix_len"] = prefix_len_dict
    table_entries.setdefault(table, []).append(entry)



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
import time
import uuid


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
# Pcap I/O
# ---------------------------------------------------------------------------

_PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4,  # magic
    2, 4,         # version
    0,            # thiszone
    0,            # sigfigs
    65535,        # snaplen
    1,            # Ethernet link type
)


def write_pcap(path: str, packets: list[bytes]) -> None:
    """Write packets to a pcap file."""
    with open(path, "wb") as f:
        f.write(_PCAP_GLOBAL_HEADER)
        for pkt in packets:
            f.write(struct.pack("<IIII", 0, 0, len(pkt), len(pkt)))
            f.write(pkt)


def read_pcap(path: str) -> list[bytes]:
    """Read packets from a pcap file. Returns empty list if file missing."""
    packets = []
    try:
        with open(path, "rb") as f:
            f.read(24)  # skip global header
            while True:
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break
                _, _, incl_len, _ = struct.unpack("<IIII", pkt_hdr)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break
                packets.append(pkt_data)
    except FileNotFoundError:
        pass
    return packets


# ---------------------------------------------------------------------------
# P4 compilation
# ---------------------------------------------------------------------------


def compile_p4(p4_path: str, out_dir: str) -> str:
    """Compile a P4 program to BMv2 JSON. Returns the JSON path."""
    json_path = os.path.join(out_dir, "program.json")
    result = subprocess.run(
        ["p4c-bm2-ss", "--std", "p4-16", "-o", json_path, p4_path],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"p4c compilation failed:\n{result.stderr}")
    return json_path


# ---------------------------------------------------------------------------
# STF to BMv2 CLI translation
# ---------------------------------------------------------------------------


def parse_stf_add(args: str) -> str:
    """Translate an STF 'add' command to a simple_switch_CLI command.

    STF format:  add <table> <action>(<params>) <key_field>:<value> ...
    CLI format:  table_add <table> <action> <key_values> => <param_values>

    The action token contains '(' and key tokens contain ':'.
    """
    tokens = args.split()
    table = tokens[0]
    action_token = ""
    key_values = []
    action_params = []
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
            _, value = token.split(":", 1)
            key_values.append(value)

    # Parse action name and parameters from "action(p1:v1, p2:v2)".
    action_name = action_token[: action_token.index("(")]
    params_str = action_token[action_token.index("(") + 1 : action_token.rindex(")")]
    if params_str.strip():
        for param in params_str.split(","):
            _, value = param.strip().split(":", 1)
            action_params.append(value.strip())

    parts = ["table_add", table, action_name] + key_values + ["=>"] + action_params
    return " ".join(parts)


def parse_stf_setdefault(args: str) -> str:
    """Translate an STF 'setdefault' command to a simple_switch_CLI command.

    STF format:  setdefault <table> <action>(<params>)
    CLI format:  table_set_default <table> <action> <param_values>
    """
    tokens = args.split()
    table = tokens[0]
    action_token = tokens[1]

    action_name = action_token[: action_token.index("(")]
    params_str = action_token[action_token.index("(") + 1 : action_token.rindex(")")]
    action_params = []
    if params_str.strip():
        for param in params_str.split(","):
            _, value = param.strip().split(":", 1)
            action_params.append(value.strip())

    parts = ["table_set_default", table, action_name] + action_params
    return " ".join(parts)


# ---------------------------------------------------------------------------
# BMv2 test driver
# ---------------------------------------------------------------------------


def _wait_for_thrift(port: int, timeout: float = 10.0) -> bool:
    """Wait for BMv2's Thrift server to accept connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("localhost", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _setup_veth_pair(name: str) -> None:
    """Create a veth pair and bring both ends up."""
    peer = f"{name}_peer"
    subprocess.run(
        ["sudo", "ip", "link", "add", name, "type", "veth", "peer", "name", peer],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["sudo", "ip", "link", "set", name, "up"], check=True, capture_output=True
    )
    subprocess.run(
        ["sudo", "ip", "link", "set", peer, "up"], check=True, capture_output=True
    )
    # Disable IPv6 to avoid spurious neighbor discovery packets.
    for iface in (name, peer):
        subprocess.run(
            ["sudo", "sysctl", "-w", f"net.ipv6.conf.{iface}.disable_ipv6=1"],
            check=True,
            capture_output=True,
        )


def _teardown_veth_pair(name: str) -> None:
    """Delete a veth pair (deleting one end removes both)."""
    subprocess.run(
        ["sudo", "ip", "link", "del", name], capture_output=True
    )


def run_stf_test(p4_path: str, stf_path: str) -> bool:
    """Run an STF test against BMv2. Returns True if all checks pass."""
    commands = parse_stf(stf_path)

    # Classify commands.
    table_cmds: list[tuple[str, str]] = []
    send_packets: list[tuple[int, str]] = []   # (port, hex_data)
    expect_packets: list[tuple[int, str | None]] = []  # (port, hex_pattern)
    ports: set[int] = set()

    for cmd, args in commands:
        if cmd == "packet":
            parts = args.split(None, 1)
            port = int(parts[0])
            hex_data = parts[1].replace(" ", "") if len(parts) > 1 else ""
            ports.add(port)
            send_packets.append((port, hex_data))
        elif cmd == "expect":
            parts = args.split(None, 1)
            port = int(parts[0])
            hex_pattern = parts[1].replace(" ", "") if len(parts) > 1 else None
            ports.add(port)
            expect_packets.append((port, hex_pattern))
        elif cmd in ("add", "setdefault"):
            table_cmds.append((cmd, args))

    # Use a unique suffix to avoid collisions between concurrent tests.
    # Veth names are limited to 15 chars, so keep the suffix short.
    suffix = uuid.uuid4().hex[:4]
    veth_names: dict[int, str] = {}
    for port in sorted(ports):
        veth_names[port] = f"stf{suffix}p{port}"

    with tempfile.TemporaryDirectory() as tmpdir:
        # Compile P4.
        json_path = compile_p4(p4_path, tmpdir)

        # Create veth pairs for BMv2 interfaces.
        for port in sorted(ports):
            _setup_veth_pair(veth_names[port])

        # Write input pcap files. With --use-files, BMv2 reads from
        # <interface_name>_in.pcap and writes to <interface_name>_out.pcap
        # in the working directory.
        pkts_by_port: dict[int, list[bytes]] = {}
        for port, hex_data in send_packets:
            pkts_by_port.setdefault(port, []).append(bytes.fromhex(hex_data))
        for port in ports:
            iface = veth_names[port]
            in_path = os.path.join(tmpdir, f"{iface}_in.pcap")
            write_pcap(in_path, pkts_by_port.get(port, []))

        # Build simple_switch command with veth interfaces and --use-files.
        # The delay gives us time to install table entries before packets
        # are processed.
        use_files_delay = 3
        iface_args: list[str] = []
        for port in sorted(ports):
            iface_args.extend(["-i", f"{port}@{veth_names[port]}"])

        thrift_port = 9090
        switch_proc = subprocess.Popen(
            [
                "simple_switch",
                "--log-file", os.path.join(tmpdir, "switch.log"),
                "--log-flush",
                "--use-files", str(use_files_delay),
                "--thrift-port", str(thrift_port),
                "--device-id", "0",
            ]
            + iface_args
            + [json_path],
            cwd=tmpdir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            # Wait for Thrift server.
            if not _wait_for_thrift(thrift_port):
                print(
                    "ERROR: Timed out waiting for simple_switch",
                    file=sys.stderr,
                )
                log_path = os.path.join(tmpdir, "switch.log")
                if os.path.exists(log_path):
                    with open(log_path) as f:
                        print(f"SWITCH LOG:\n{f.read()}", file=sys.stderr)
                return False

            # Install table entries.
            if table_cmds:
                cli_lines = []
                for cmd, args in table_cmds:
                    if cmd == "add":
                        cli_lines.append(parse_stf_add(args))
                    elif cmd == "setdefault":
                        cli_lines.append(parse_stf_setdefault(args))
                cli_input = "\n".join(cli_lines) + "\n"
                cli_result = subprocess.run(
                    ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
                    input=cli_input,
                    capture_output=True,
                    text=True,
                )
                if cli_result.returncode != 0:
                    print(
                        f"CLI failed: {cli_result.stderr}",
                        file=sys.stderr,
                    )
                    return False

            # Wait for BMv2 to process packets (delay + processing time).
            time.sleep(use_files_delay + 2)

            # Read output pcap files.
            output_by_port: dict[int, list[bytes]] = {}
            for port in ports:
                iface = veth_names[port]
                out_path = os.path.join(tmpdir, f"{iface}_out.pcap")
                output_by_port[port] = read_pcap(out_path)

            # Verify expected packets.
            passed = True
            for port, pattern in expect_packets:
                actuals = output_by_port.get(port, [])
                if not actuals:
                    print(f"FAIL: expected packet on port {port}, got nothing")
                    passed = False
                    continue
                actual = actuals.pop(0)
                actual_hex = actual.hex()
                if pattern is not None and not match_hex(actual_hex, pattern):
                    print(f"FAIL: packet mismatch on port {port}")
                    print(f"  expected: {pattern}")
                    print(f"  actual:   {actual_hex}")
                    passed = False

            if passed:
                print("PASS: all expected packets matched")
            return passed

        finally:
            switch_proc.terminate()
            try:
                switch_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                switch_proc.kill()
                switch_proc.wait()
            # Clean up veth pairs.
            for port in sorted(ports):
                _teardown_veth_pair(veth_names[port])


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="Run an STF test against BMv2")
    parser.add_argument("p4_program", help="Path to the .p4 file")
    parser.add_argument("stf_file", help="Path to the .stf file")
    args = parser.parse_args()

    if not run_stf_test(args.p4_program, args.stf_file):
        sys.exit(1)


if __name__ == "__main__":
    main()

"""Unit tests for the STF runner's parser and hex matcher."""

import unittest

from tests.infra.stf_runner import (
    match_hex,
    parse_stf_string,
    stf_to_sim_inputs,
)


class TestParseStf(unittest.TestCase):
    def test_empty(self):
        assert parse_stf_string("") == []

    def test_comments_and_blank_lines(self):
        assert parse_stf_string("# comment\n\n# another\n") == []

    def test_packet(self):
        cmds = parse_stf_string("packet 1 AABB CCDD\n")
        assert cmds == [("packet", "1 AABB CCDD")]

    def test_expect(self):
        cmds = parse_stf_string("expect 2 AABB CCDD\n")
        assert cmds == [("expect", "2 AABB CCDD")]

    def test_add(self):
        line = "add MyIngress.t MyIngress.a(p:1) f:0x01\n"
        cmds = parse_stf_string(line)
        assert cmds == [("add", "MyIngress.t MyIngress.a(p:1) f:0x01")]

    def test_setdefault(self):
        cmds = parse_stf_string("setdefault MyIngress.t MyIngress.drop()\n")
        assert cmds == [("setdefault", "MyIngress.t MyIngress.drop()")]

    def test_mixed(self):
        stf = "# Setup\nadd T A(p:1) k:0x01\n\npacket 0 AABB\nexpect 1 AABB\n"
        cmds = parse_stf_string(stf)
        assert len(cmds) == 3
        assert cmds[0][0] == "add"
        assert cmds[1][0] == "packet"
        assert cmds[2][0] == "expect"


class TestMatchHex(unittest.TestCase):
    def test_exact_match(self):
        assert match_hex("aabb", "aabb")

    def test_exact_mismatch(self):
        assert not match_hex("aabb", "ccdd")

    def test_wildcard(self):
        assert match_hex("aabb", "aa**")

    def test_wildcard_mismatch(self):
        assert not match_hex("aabb", "cc**")

    def test_case_insensitive(self):
        assert match_hex("AABB", "aabb")

    def test_different_lengths(self):
        assert not match_hex("aabb", "aabbcc")


class TestStfToSimInputs(unittest.TestCase):
    def test_basic_forward(self):
        stf = (
            "add MyIngress.mac_table MyIngress.forward(port:2)"
            " hdr.ethernet.dstAddr:0x000000000001\n"
            "packet 1 000000000001 000000000002 0800\n"
            "expect 2 000000000001 000000000002 0800\n"
        )
        result = stf_to_sim_inputs(stf)
        assert result.table_entries == {
            "mac_table": [
                {
                    "key": {"hdr.ethernet.dstAddr": 0x000000000001},
                    "action": "forward",
                    "args": {"port": 2},
                },
            ],
        }
        assert len(result.packets) == 1
        assert result.packets[0].port == 1
        assert result.packets[0].data == bytes.fromhex("0000000000010000000000020800")
        assert len(result.expects) == 1
        assert result.expects[0].port == 2
        assert result.expects[0].pattern == "0000000000010000000000020800"

    def test_no_table_entries(self):
        stf = "packet 0 AABB\nexpect 1 AABB\n"
        result = stf_to_sim_inputs(stf)
        assert result.table_entries == {}
        assert len(result.packets) == 1
        assert len(result.expects) == 1

    def test_multiple_packets(self):
        stf = "packet 0 AA\npacket 1 BB\nexpect 0 BB\nexpect 1 AA\n"
        result = stf_to_sim_inputs(stf)
        assert len(result.packets) == 2
        assert len(result.expects) == 2
        assert result.packets[0].port == 0
        assert result.packets[1].port == 1

    def test_expect_end_of_packet_marker(self):
        stf = "packet 0 AABB\nexpect 1 AABB$\n"
        result = stf_to_sim_inputs(stf)
        assert result.expects[0].pattern == "aabb"

    def test_lpm_prefix_notation(self):
        stf = (
            "add ingress.ipv4_lpm ingress.forward(port:1)"
            " hdr.ipv4.dstAddr:0x0A000000/24\n"
            "packet 0 AA\n"
        )
        result = stf_to_sim_inputs(stf)
        entry = result.table_entries["ipv4_lpm"][0]
        assert entry["key"] == {"hdr.ipv4.dstAddr": 0x0A000000}
        assert entry["prefix_len"] == {"hdr.ipv4.dstAddr": 24}
        assert entry["action"] == "forward"
        assert entry["args"] == {"port": 1}

    def test_mixed_exact_and_lpm_keys(self):
        stf = "add T A(p:1) k1:0xAA k2:0xBB/16\npacket 0 AA\n"
        result = stf_to_sim_inputs(stf)
        entry = result.table_entries["T"][0]
        assert entry["key"] == {"k1": 0xAA, "k2": 0xBB}
        assert entry["prefix_len"] == {"k2": 16}

    def test_quoted_identifiers(self):
        """p4testgen generates STF with quoted identifiers."""
        stf = (
            'add "MyIngress.mac_table" "hdr.ethernet.dstAddr":0x000000000001'
            ' "MyIngress.forward"("port":0x002)\n'
            "packet 0 000000000001000000000002 0800\n"
            "expect 2 000000000001000000000002 0800\n"
        )
        result = stf_to_sim_inputs(stf)
        assert result.table_entries == {
            "mac_table": [
                {
                    "key": {"hdr.ethernet.dstAddr": 0x000000000001},
                    "action": "forward",
                    "args": {"port": 2},
                },
            ],
        }

    def test_drop_test_no_expect(self):
        stf = "add T A()\npacket 0 AABB\n"
        result = stf_to_sim_inputs(stf)
        assert len(result.packets) == 1
        assert len(result.expects) == 0


if __name__ == "__main__":
    unittest.main()

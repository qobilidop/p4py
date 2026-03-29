"""Unit tests for the STF runner's parser and hex matcher."""

from absl.testing import absltest

from tests.infra.stf_runner import (
    match_hex,
    parse_stf_string,
    stf_to_sim_inputs,
)


class TestParseStf(absltest.TestCase):
    def test_empty(self):
        self.assertEqual(parse_stf_string(""), [])

    def test_comments_and_blank_lines(self):
        self.assertEqual(parse_stf_string("# comment\n\n# another\n"), [])

    def test_packet(self):
        cmds = parse_stf_string("packet 1 AABB CCDD\n")
        self.assertEqual(cmds, [("packet", "1 AABB CCDD")])

    def test_expect(self):
        cmds = parse_stf_string("expect 2 AABB CCDD\n")
        self.assertEqual(cmds, [("expect", "2 AABB CCDD")])

    def test_add(self):
        line = "add MyIngress.t MyIngress.a(p:1) f:0x01\n"
        cmds = parse_stf_string(line)
        self.assertEqual(cmds, [("add", "MyIngress.t MyIngress.a(p:1) f:0x01")])

    def test_setdefault(self):
        cmds = parse_stf_string("setdefault MyIngress.t MyIngress.drop()\n")
        self.assertEqual(cmds, [("setdefault", "MyIngress.t MyIngress.drop()")])

    def test_mixed(self):
        stf = "# Setup\nadd T A(p:1) k:0x01\n\npacket 0 AABB\nexpect 1 AABB\n"
        cmds = parse_stf_string(stf)
        self.assertLen(cmds, 3)
        self.assertEqual(cmds[0][0], "add")
        self.assertEqual(cmds[1][0], "packet")
        self.assertEqual(cmds[2][0], "expect")


class TestMatchHex(absltest.TestCase):
    def test_exact_match(self):
        self.assertTrue(match_hex("aabb", "aabb"))

    def test_exact_mismatch(self):
        self.assertFalse(match_hex("aabb", "ccdd"))

    def test_wildcard(self):
        self.assertTrue(match_hex("aabb", "aa**"))

    def test_wildcard_mismatch(self):
        self.assertFalse(match_hex("aabb", "cc**"))

    def test_case_insensitive(self):
        self.assertTrue(match_hex("AABB", "aabb"))

    def test_different_lengths(self):
        self.assertFalse(match_hex("aabb", "aabbcc"))


class TestStfToSimInputs(absltest.TestCase):
    def test_basic_forward(self):
        stf = (
            "add MyIngress.mac_table MyIngress.forward(port:2)"
            " hdr.ethernet.dstAddr:0x000000000001\n"
            "packet 1 000000000001 000000000002 0800\n"
            "expect 2 000000000001 000000000002 0800\n"
        )
        result = stf_to_sim_inputs(stf)
        self.assertEqual(
            result.table_entries,
            {
                "mac_table": [
                    {
                        "key": {"hdr.ethernet.dstAddr": 0x000000000001},
                        "action": "forward",
                        "args": {"port": 2},
                    },
                ],
            },
        )
        self.assertLen(result.packets, 1)
        self.assertEqual(result.packets[0].port, 1)
        self.assertEqual(
            result.packets[0].data, bytes.fromhex("0000000000010000000000020800")
        )
        self.assertLen(result.expects, 1)
        self.assertEqual(result.expects[0].port, 2)
        self.assertEqual(result.expects[0].pattern, "0000000000010000000000020800")

    def test_no_table_entries(self):
        stf = "packet 0 AABB\nexpect 1 AABB\n"
        result = stf_to_sim_inputs(stf)
        self.assertEqual(result.table_entries, {})
        self.assertLen(result.packets, 1)
        self.assertLen(result.expects, 1)

    def test_multiple_packets(self):
        stf = "packet 0 AA\npacket 1 BB\nexpect 0 BB\nexpect 1 AA\n"
        result = stf_to_sim_inputs(stf)
        self.assertLen(result.packets, 2)
        self.assertLen(result.expects, 2)
        self.assertEqual(result.packets[0].port, 0)
        self.assertEqual(result.packets[1].port, 1)

    def test_expect_end_of_packet_marker(self):
        stf = "packet 0 AABB\nexpect 1 AABB$\n"
        result = stf_to_sim_inputs(stf)
        self.assertEqual(result.expects[0].pattern, "aabb")

    def test_lpm_prefix_notation(self):
        stf = (
            "add ingress.ipv4_lpm ingress.forward(port:1)"
            " hdr.ipv4.dstAddr:0x0A000000/24\n"
            "packet 0 AA\n"
        )
        result = stf_to_sim_inputs(stf)
        entry = result.table_entries["ipv4_lpm"][0]
        self.assertEqual(entry["key"], {"hdr.ipv4.dstAddr": 0x0A000000})
        self.assertEqual(entry["prefix_len"], {"hdr.ipv4.dstAddr": 24})
        self.assertEqual(entry["action"], "forward")
        self.assertEqual(entry["args"], {"port": 1})

    def test_mixed_exact_and_lpm_keys(self):
        stf = "add T A(p:1) k1:0xAA k2:0xBB/16\npacket 0 AA\n"
        result = stf_to_sim_inputs(stf)
        entry = result.table_entries["T"][0]
        self.assertEqual(entry["key"], {"k1": 0xAA, "k2": 0xBB})
        self.assertEqual(entry["prefix_len"], {"k2": 16})

    def test_quoted_identifiers(self):
        """p4testgen generates STF with quoted identifiers."""
        stf = (
            'add "MyIngress.mac_table" "hdr.ethernet.dstAddr":0x000000000001'
            ' "MyIngress.forward"("port":0x002)\n'
            "packet 0 000000000001000000000002 0800\n"
            "expect 2 000000000001000000000002 0800\n"
        )
        result = stf_to_sim_inputs(stf)
        self.assertEqual(
            result.table_entries,
            {
                "mac_table": [
                    {
                        "key": {"hdr.ethernet.dstAddr": 0x000000000001},
                        "action": "forward",
                        "args": {"port": 2},
                    },
                ],
            },
        )

    def test_drop_test_no_expect(self):
        stf = "add T A()\npacket 0 AABB\n"
        result = stf_to_sim_inputs(stf)
        self.assertLen(result.packets, 1)
        self.assertLen(result.expects, 0)


if __name__ == "__main__":
    absltest.main()

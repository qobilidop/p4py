"""Unit tests for the STF runner's parser and hex matcher."""

from e2e_tests.stf_runner import match_hex, parse_stf_string


class TestParseStf:
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
        stf = (
            "# Setup\n"
            "add T A(p:1) k:0x01\n"
            "\n"
            "packet 0 AABB\n"
            "expect 1 AABB\n"
        )
        cmds = parse_stf_string(stf)
        assert len(cmds) == 3
        assert cmds[0][0] == "add"
        assert cmds[1][0] == "packet"
        assert cmds[2][0] == "expect"


class TestMatchHex:
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

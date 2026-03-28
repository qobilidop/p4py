"""Tests for p4py.lang.bit."""

import p4py.lang as p4


class TestBit:
    def test_creates_type(self):
        t = p4.bit(8)
        assert t.width == 8

    def test_different_widths_are_different(self):
        assert p4.bit(8) != p4.bit(16)

    def test_same_widths_are_equal(self):
        assert p4.bit(8) == p4.bit(8)

    def test_repr(self):
        assert repr(p4.bit(48)) == "bit(48)"

    def test_used_as_annotation(self):
        class MyHeader:
            dstAddr: p4.bit(48)

        ann = MyHeader.__annotations__
        assert ann["dstAddr"] == p4.bit(48)

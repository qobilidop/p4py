"""Tests for p4py.lang.bit."""

from p4py.lang.bit import bit


class TestBit:
    def test_creates_type(self):
        t = bit(8)
        assert t.width == 8

    def test_different_widths_are_different(self):
        assert bit(8) != bit(16)

    def test_same_widths_are_equal(self):
        assert bit(8) == bit(8)

    def test_repr(self):
        assert repr(bit(48)) == "bit(48)"

    def test_used_as_annotation(self):
        class MyHeader:
            dstAddr: bit(48)

        ann = MyHeader.__annotations__
        assert ann["dstAddr"] == bit(48)

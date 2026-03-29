"""Tests for p4py.lang.bit."""

from absl.testing import absltest

import p4py.lang as p4


class TestBit(absltest.TestCase):
    def test_creates_type(self):
        t = p4.bit(8)
        self.assertEqual(t.width, 8)

    def test_different_widths_are_different(self):
        self.assertNotEqual(p4.bit(8), p4.bit(16))

    def test_same_widths_are_equal(self):
        self.assertEqual(p4.bit(8), p4.bit(8))

    def test_repr(self):
        self.assertEqual(repr(p4.bit(48)), "bit(48)")

    def test_used_as_annotation(self):
        class MyHeader:
            dstAddr: p4.bit(48)

        ann = MyHeader.__annotations__
        self.assertEqual(ann["dstAddr"], p4.bit(48))


class TestBoolType(absltest.TestCase):
    def test_bool_is_singleton(self):
        self.assertIs(p4.bool, p4.bool)

    def test_bool_repr(self):
        self.assertEqual(repr(p4.bool), "bool")

    def test_bool_is_not_bit(self):
        self.assertNotIsInstance(p4.bool, p4.BitType)


class TestNoAction(absltest.TestCase):
    def test_noaction_name(self):
        self.assertEqual(p4.NoAction._p4_name, "NoAction")


if __name__ == "__main__":
    absltest.main()

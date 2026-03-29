"""Tests for p4py.lang.header."""

from absl.testing import absltest

import p4py.lang as p4


class TestHeader(absltest.TestCase):
    def test_fields_extracted_from_annotations(self):
        class ethernet_t(p4.header):
            dstAddr: p4.bit(48)
            srcAddr: p4.bit(48)
            etherType: p4.bit(16)

        self.assertEqual(
            ethernet_t._p4_fields,
            (
                ("dstAddr", p4.bit(48)),
                ("srcAddr", p4.bit(48)),
                ("etherType", p4.bit(16)),
            ),
        )

    def test_name_from_class(self):
        class ipv4_t(p4.header):
            srcAddr: p4.bit(32)
            dstAddr: p4.bit(32)

        self.assertEqual(ipv4_t._p4_name, "ipv4_t")

    def test_total_bit_width(self):
        class ethernet_t(p4.header):
            dstAddr: p4.bit(48)
            srcAddr: p4.bit(48)
            etherType: p4.bit(16)

        self.assertEqual(ethernet_t._p4_bit_width, 112)

    def test_empty_header_rejected(self):
        with self.assertRaises(TypeError) as cm:

            class empty_t(p4.header):
                pass

        self.assertIn("at least one field", str(cm.exception))

    def test_non_bit_annotation_rejected(self):
        with self.assertRaises(TypeError) as cm:

            class bad_t(p4.header):
                x: int

        self.assertIn("bit", str(cm.exception).lower())


if __name__ == "__main__":
    absltest.main()

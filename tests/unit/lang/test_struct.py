"""Tests for p4py.lang.struct."""

from absl.testing import absltest

import p4py.lang as p4


class TestStruct(absltest.TestCase):
    def test_members_extracted(self):
        class eth_t(p4.header):
            x: p4.bit(8)

        class headers_t(p4.struct):
            ethernet: eth_t

        self.assertEqual(headers_t._p4_members, (("ethernet", eth_t),))

    def test_name_from_class(self):
        class metadata_t(p4.struct):
            pass

        self.assertEqual(metadata_t._p4_name, "metadata_t")

    def test_empty_struct_allowed(self):
        class metadata_t(p4.struct):
            pass

        self.assertEqual(metadata_t._p4_members, ())

    def test_bit_field_members(self):
        class meta_t(p4.struct):
            vrf: p4.bit(12)
            bd: p4.bit(16)

        self.assertLen(meta_t._p4_members, 2)
        self.assertEqual(meta_t._p4_members[0], ("vrf", p4.bit(12)))
        self.assertEqual(meta_t._p4_members[1], ("bd", p4.bit(16)))

    def test_nested_struct_members(self):
        class inner_t(p4.struct):
            vrf: p4.bit(12)
            bd: p4.bit(16)

        class outer_t(p4.struct):
            ingress_metadata: inner_t

        self.assertLen(outer_t._p4_members, 1)
        self.assertEqual(outer_t._p4_members[0], ("ingress_metadata", inner_t))

    def test_non_header_non_bit_annotation_rejected(self):
        with self.assertRaises(TypeError) as cm:

            class bad_t(p4.struct):
                x: int

        msg = str(cm.exception).lower()
        self.assertTrue("header" in msg or "bit" in msg)


if __name__ == "__main__":
    absltest.main()

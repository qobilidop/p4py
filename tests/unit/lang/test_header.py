"""Tests for p4py.lang.header."""

import p4py.lang as p4


class TestHeader:
    def test_fields_extracted_from_annotations(self):
        class ethernet_t(p4.header):
            dstAddr: p4.bit(48)
            srcAddr: p4.bit(48)
            etherType: p4.bit(16)

        assert ethernet_t._p4_fields == (
            ("dstAddr", p4.bit(48)),
            ("srcAddr", p4.bit(48)),
            ("etherType", p4.bit(16)),
        )

    def test_name_from_class(self):
        class ipv4_t(p4.header):
            srcAddr: p4.bit(32)
            dstAddr: p4.bit(32)

        assert ipv4_t._p4_name == "ipv4_t"

    def test_total_bit_width(self):
        class ethernet_t(p4.header):
            dstAddr: p4.bit(48)
            srcAddr: p4.bit(48)
            etherType: p4.bit(16)

        assert ethernet_t._p4_bit_width == 112

    def test_empty_header_rejected(self):
        try:

            class empty_t(p4.header):
                pass

            raise AssertionError("Expected TypeError")
        except TypeError as e:
            assert "at least one field" in str(e)

    def test_non_bit_annotation_rejected(self):
        try:

            class bad_t(p4.header):
                x: int

            raise AssertionError("Expected TypeError")
        except TypeError as e:
            assert "bit" in str(e).lower()

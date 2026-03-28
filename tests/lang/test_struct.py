"""Tests for p4py.lang.struct."""

from p4py.lang.bit import bit
from p4py.lang.header import header
from p4py.lang.struct import struct


class TestStruct:
    def test_members_extracted(self):
        class eth_t(header):
            x: bit(8)

        class headers_t(struct):
            ethernet: eth_t

        assert headers_t._p4_members == (("ethernet", eth_t),)

    def test_name_from_class(self):
        class metadata_t(struct):
            pass

        assert metadata_t._p4_name == "metadata_t"

    def test_empty_struct_allowed(self):
        class metadata_t(struct):
            pass

        assert metadata_t._p4_members == ()

    def test_non_header_annotation_rejected(self):
        try:

            class bad_t(struct):
                x: int

            raise AssertionError("Expected TypeError")
        except TypeError as e:
            assert "header" in str(e).lower()

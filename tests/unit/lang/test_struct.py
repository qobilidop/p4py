"""Tests for p4py.lang.struct."""

import p4py.lang as p4


class TestStruct:
    def test_members_extracted(self):
        class eth_t(p4.header):
            x: p4.bit(8)

        class headers_t(p4.struct):
            ethernet: eth_t

        assert headers_t._p4_members == (("ethernet", eth_t),)

    def test_name_from_class(self):
        class metadata_t(p4.struct):
            pass

        assert metadata_t._p4_name == "metadata_t"

    def test_empty_struct_allowed(self):
        class metadata_t(p4.struct):
            pass

        assert metadata_t._p4_members == ()

    def test_bit_field_members(self):
        class meta_t(p4.struct):
            vrf: p4.bit(12)
            bd: p4.bit(16)

        assert len(meta_t._p4_members) == 2
        assert meta_t._p4_members[0] == ("vrf", p4.bit(12))
        assert meta_t._p4_members[1] == ("bd", p4.bit(16))

    def test_non_header_non_bit_annotation_rejected(self):
        try:

            class bad_t(p4.struct):
                x: int

            raise AssertionError("Expected TypeError")
        except TypeError as e:
            assert "header" in str(e).lower() or "bit" in str(e).lower()

"""Tests for emitting declaration types."""

from absl.testing import absltest

from p4py import ir
from p4py.emitter.p4 import (
    _emit_typedef,
    _emit_newtype,
    _emit_enum,
    _emit_const,
)


class TestEmitTypedef(absltest.TestCase):
    def test_emit(self):
        td = ir.TypedefDecl(name="ethernet_addr_t", type=ir.BitType(48))
        lines = []
        _emit_typedef(lines, td)
        self.assertEqual(lines, ["typedef bit<48> ethernet_addr_t;"])


class TestEmitNewtype(absltest.TestCase):
    def test_emit(self):
        nt = ir.NewtypeDecl(name="port_id_t", type=ir.BitType(9))
        lines = []
        _emit_newtype(lines, nt)
        self.assertEqual(lines, ["type bit<9> port_id_t;"])


class TestEmitEnum(absltest.TestCase):
    def test_emit(self):
        e = ir.EnumDecl(
            name="MeterColor_t",
            underlying_type=ir.BitType(2),
            members=(
                ir.EnumMember("GREEN", 0),
                ir.EnumMember("YELLOW", 1),
                ir.EnumMember("RED", 2),
            ),
        )
        lines = []
        _emit_enum(lines, e)
        expected = [
            "enum bit<2> MeterColor_t {",
            "    GREEN = 0,",
            "    YELLOW = 1,",
            "    RED = 2",
            "};",
            "",
        ]
        self.assertEqual(lines, expected)


class TestEmitConst(absltest.TestCase):
    def test_emit(self):
        c = ir.ConstDecl(name="INTERNAL_VLAN_ID", type_name="vlan_id_t", value=0xFFF)
        lines = []
        _emit_const(lines, c)
        self.assertEqual(lines, ["const vlan_id_t INTERNAL_VLAN_ID = 0x0fff;"])

    def test_emit_small_value(self):
        c = ir.ConstDecl(name="kDefaultVrf", type_name="vrf_id_t", value=0)
        lines = []
        _emit_const(lines, c)
        self.assertEqual(lines, ["const vrf_id_t kDefaultVrf = 0;"])


if __name__ == "__main__":
    absltest.main()

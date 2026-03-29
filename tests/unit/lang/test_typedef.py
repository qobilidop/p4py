"""Tests for p4py.lang typedef, newtype, enum, and const."""

from absl.testing import absltest

import p4py.lang as p4


class TestTypedef(absltest.TestCase):
    def test_basic(self):
        EthernetAddress = p4.typedef(p4.bit(48), "EthernetAddress")
        self.assertEqual(EthernetAddress._p4_name, "EthernetAddress")
        self.assertEqual(EthernetAddress._p4_underlying, p4.bit(48))
        self.assertEqual(EthernetAddress._p4_kind, "typedef")
        self.assertEqual(EthernetAddress.width, 48)

    def test_header_field_accepts_named_type(self):
        EthernetAddress = p4.typedef(p4.bit(48), "EthernetAddress")

        class ethernet_t(p4.header):
            dstAddr: EthernetAddress
            etherType: p4.bit(16)

        self.assertEqual(ethernet_t._p4_fields[0], ("dstAddr", EthernetAddress))

    def test_struct_member_accepts_named_type(self):
        MyBit = p4.typedef(p4.bit(12), "MyBit")

        class meta_t(p4.struct):
            vrf: MyBit

        self.assertEqual(meta_t._p4_members[0], ("vrf", MyBit))


class TestEnum(absltest.TestCase):
    def test_basic(self):
        class MeterColor_t(p4.enum(p4.bit(2))):
            GREEN = 0
            YELLOW = 1
            RED = 2

        self.assertEqual(MeterColor_t._p4_name, "MeterColor_t")
        self.assertEqual(MeterColor_t._p4_underlying, p4.bit(2))
        self.assertEqual(MeterColor_t._p4_kind, "enum")
        self.assertEqual(MeterColor_t.width, 2)
        self.assertEqual(
            MeterColor_t._p4_members,
            (("GREEN", 0), ("YELLOW", 1), ("RED", 2)),
        )

    def test_struct_member_accepts_enum(self):
        class Color_t(p4.enum(p4.bit(2))):
            A = 0
            B = 1

        class meta_t(p4.struct):
            color: Color_t

        self.assertEqual(meta_t._p4_members[0], ("color", Color_t))


class TestConst(absltest.TestCase):
    def test_basic(self):
        PortId_t = p4.newtype(p4.bit(9), "PortId_t")
        PORT_CPU = p4.const(PortId_t, 255, "PORT_CPU")
        self.assertEqual(PORT_CPU._p4_name, "PORT_CPU")
        self.assertEqual(PORT_CPU._p4_type_name, "PortId_t")
        self.assertEqual(PORT_CPU._p4_value, 255)
        self.assertEqual(PORT_CPU._p4_kind, "const")

    def test_with_typedef(self):
        MyType = p4.typedef(p4.bit(8), "MyType")
        MY_CONST = p4.const(MyType, 42, "MY_CONST")
        self.assertEqual(MY_CONST._p4_type_name, "MyType")
        self.assertEqual(MY_CONST._p4_value, 42)


class TestNewtype(absltest.TestCase):
    def test_basic(self):
        PortId_t = p4.newtype(p4.bit(9), "PortId_t")
        self.assertEqual(PortId_t._p4_name, "PortId_t")
        self.assertEqual(PortId_t._p4_underlying, p4.bit(9))
        self.assertEqual(PortId_t._p4_kind, "newtype")
        self.assertEqual(PortId_t.width, 9)

    def test_struct_member_accepts_newtype(self):
        PortId_t = p4.newtype(p4.bit(9), "PortId_t")

        class meta_t(p4.struct):
            port: PortId_t

        self.assertEqual(meta_t._p4_members[0], ("port", PortId_t))


if __name__ == "__main__":
    absltest.main()

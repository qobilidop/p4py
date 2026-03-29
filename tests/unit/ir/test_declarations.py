"""Tests for P4 IR declaration node types."""

from dataclasses import FrozenInstanceError

from absl.testing import absltest

from p4py import ir


class TestTypedefDecl(absltest.TestCase):
    def test_creation(self):
        decl = ir.TypedefDecl(name="EthernetAddress", type=ir.BitType(48))
        self.assertEqual(decl.name, "EthernetAddress")
        self.assertEqual(decl.type, ir.BitType(48))

    def test_frozen(self):
        decl = ir.TypedefDecl(name="EthernetAddress", type=ir.BitType(48))
        with self.assertRaises(FrozenInstanceError):
            decl.name = "other"


class TestEnumDecl(absltest.TestCase):
    def test_creation(self):
        decl = ir.EnumDecl(
            name="MeterColor_t",
            underlying_type=ir.BitType(2),
            members=(
                ir.EnumMember(name="GREEN", value=0),
                ir.EnumMember(name="YELLOW", value=1),
                ir.EnumMember(name="RED", value=2),
            ),
        )
        self.assertEqual(decl.name, "MeterColor_t")
        self.assertEqual(decl.underlying_type, ir.BitType(2))
        self.assertLen(decl.members, 3)
        self.assertEqual(decl.members[0].name, "GREEN")
        self.assertEqual(decl.members[0].value, 0)

    def test_frozen(self):
        decl = ir.EnumDecl(
            name="Color",
            underlying_type=ir.BitType(2),
            members=(ir.EnumMember(name="A", value=0),),
        )
        with self.assertRaises(FrozenInstanceError):
            decl.name = "other"

    def test_member_frozen(self):
        m = ir.EnumMember(name="GREEN", value=0)
        with self.assertRaises(FrozenInstanceError):
            m.name = "other"


class TestNewtypeDecl(absltest.TestCase):
    def test_creation(self):
        decl = ir.NewtypeDecl(name="PortId_t", type=ir.BitType(9))
        self.assertEqual(decl.name, "PortId_t")
        self.assertEqual(decl.type, ir.BitType(9))

    def test_frozen(self):
        decl = ir.NewtypeDecl(name="PortId_t", type=ir.BitType(9))
        with self.assertRaises(FrozenInstanceError):
            decl.name = "other"


if __name__ == "__main__":
    absltest.main()

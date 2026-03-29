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


if __name__ == "__main__":
    absltest.main()

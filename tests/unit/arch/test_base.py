"""Tests for architecture base classes."""

from absl.testing import absltest

from p4py.arch.base import BlockSpec


class TestBlockSpec(absltest.TestCase):
    def test_required_by_default(self):
        spec = BlockSpec(name="parser", kind="parser")
        self.assertEqual(spec.name, "parser")
        self.assertEqual(spec.kind, "parser")
        self.assertTrue(spec.required)

    def test_optional_block(self):
        spec = BlockSpec(name="egress", kind="control", required=False)
        self.assertFalse(spec.required)


if __name__ == "__main__":
    absltest.main()

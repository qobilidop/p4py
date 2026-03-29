"""Smoke test for p4py package."""

from absl.testing import absltest

import p4py


class TestVersion(absltest.TestCase):
    def test_version(self):
        self.assertEqual(p4py.__version__, "0.0.1")


if __name__ == "__main__":
    absltest.main()

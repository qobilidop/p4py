"""Tests for p4py.arch.ebpf_model."""

from absl.testing import absltest

import p4py.lang as p4
from p4py.arch.ebpf_model import array_table, ebpfFilter, hash_table


class TestHashTable(absltest.TestCase):
    def test_creates_table_impl(self):
        impl = hash_table(64)
        self.assertEqual(impl._p4_kind, "table_impl")
        self.assertEqual(impl._p4_name, "hash_table")
        self.assertEqual(impl._p4_size, 64)


class TestArrayTable(absltest.TestCase):
    def test_creates_table_impl(self):
        impl = array_table(1024)
        self.assertEqual(impl._p4_kind, "table_impl")
        self.assertEqual(impl._p4_name, "array_table")
        self.assertEqual(impl._p4_size, 1024)


class TestEbpfFilter(absltest.TestCase):
    def test_creates_pipeline(self):
        class Eth(p4.header):
            x: p4.bit(8)

        class Hdrs(p4.struct):
            ethernet: Eth

        @p4.parser
        def prs(p, headers: Hdrs):
            def start():
                return p4.ACCEPT

        @p4.control
        def pipe(headers: Hdrs, accept):
            pass

        pipeline = ebpfFilter(parser=prs, filter=pipe)
        self.assertEqual(pipeline.parser._p4_name, "prs")
        self.assertEqual(pipeline.filter._p4_name, "pipe")
        self.assertIs(pipeline.headers, Hdrs)


if __name__ == "__main__":
    absltest.main()

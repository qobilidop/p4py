"""Tests for p4py.arch.ebpf_model."""

from absl.testing import absltest

import p4py.lang as p4
from p4py.arch import ebpf_model
from p4py.arch.ebpf_model import EbpfFilterArch, array_table, ebpfFilter, hash_table


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


class TestEbpfFilterArch(absltest.TestCase):
    def test_include(self):
        arch = EbpfFilterArch()
        self.assertEqual(arch.include, "ebpf_model.p4")

    def test_pipeline_has_two_blocks(self):
        arch = EbpfFilterArch()
        self.assertLen(arch.pipeline, 2)
        names = [s.name for s in arch.pipeline]
        self.assertEqual(names, ["parser", "filter"])

    def test_all_blocks_required(self):
        arch = EbpfFilterArch()
        for spec in arch.pipeline:
            self.assertTrue(spec.required)

    def test_ebpf_filter_has_arch(self):
        filt = ebpf_model.ebpfFilter()
        self.assertIsInstance(filt.arch, EbpfFilterArch)

    def test_block_signature_parser(self):
        arch = EbpfFilterArch()
        names = {"headers": "Headers_t"}
        sig = arch.block_signature("parser", names)
        self.assertIn("packet_in", sig)
        self.assertIn("Headers_t", sig)
        self.assertNotIn("standard_metadata_t", sig)

    def test_block_signature_filter(self):
        arch = EbpfFilterArch()
        names = {"headers": "Headers_t"}
        sig = arch.block_signature("filter", names)
        self.assertIn("inout Headers_t", sig)
        self.assertIn("out bool pass_", sig)

    def test_main_instantiation(self):
        arch = EbpfFilterArch()
        block_names = {"parser": "prs", "filter": "pipe"}
        main = arch.main_instantiation(block_names)
        self.assertEqual(main, "ebpfFilter(prs(), pipe()) main;")


if __name__ == "__main__":
    absltest.main()

"""Tests for p4py.arch.v1model and language surface."""

from absl.testing import absltest

import p4py.lang as p4
from p4py.arch.v1model import V1Switch, mark_to_drop, standard_metadata_t


class TestLangSurface(absltest.TestCase):
    def test_parser_decorator_returns_spec(self):
        @p4.parser
        def MyParser(pkt, hdr, meta, std_meta):
            def start():
                return p4.ACCEPT

        self.assertEqual(MyParser._p4_kind, "parser")
        self.assertEqual(MyParser._p4_name, "MyParser")

    def test_parser_decorator_captures_annotations(self):
        class my_hdrs(p4.struct):
            pass

        class my_meta(p4.struct):
            pass

        @p4.parser
        def MyParser(pkt, hdr: my_hdrs, meta: my_meta, std_meta):
            def start():
                return p4.ACCEPT

        self.assertEqual(MyParser._p4_annotations, {"hdr": my_hdrs, "meta": my_meta})

    def test_control_decorator_returns_spec(self):
        @p4.control
        def MyIngress(hdr, meta, std_meta):
            pass

        self.assertEqual(MyIngress._p4_kind, "control")
        self.assertEqual(MyIngress._p4_name, "MyIngress")

    def test_deparser_decorator_returns_spec(self):
        @p4.deparser
        def MyDeparser(pkt, hdr):
            pass

        self.assertEqual(MyDeparser._p4_kind, "deparser")
        self.assertEqual(MyDeparser._p4_name, "MyDeparser")

    def test_sentinels_exist(self):
        self.assertIsNotNone(p4.exact)
        self.assertIsNotNone(p4.ACCEPT)
        self.assertIsNotNone(p4.REJECT)
        self.assertIsNotNone(p4.action)
        self.assertIsNotNone(p4.table)


class TestStandardMetadata(absltest.TestCase):
    def test_is_header_subclass(self):
        self.assertTrue(issubclass(standard_metadata_t, p4.header))

    def test_has_ingress_port(self):
        fields = dict(standard_metadata_t._p4_fields)
        self.assertEqual(fields["ingress_port"], p4.bit(9))

    def test_has_egress_spec(self):
        fields = dict(standard_metadata_t._p4_fields)
        self.assertEqual(fields["egress_spec"], p4.bit(9))


class TestMarkToDrop(absltest.TestCase):
    def test_is_callable_sentinel(self):
        self.assertEqual(mark_to_drop._p4_kind, "extern")
        self.assertEqual(mark_to_drop._p4_name, "mark_to_drop")


class TestV1Switch(absltest.TestCase):
    def test_creates_pipeline(self):
        class eth_t(p4.header):
            x: p4.bit(8)

        class hdrs_t(p4.struct):
            ethernet: eth_t

        class meta_t(p4.struct):
            pass

        @p4.parser
        def P(pkt, hdr: hdrs_t, meta: meta_t, std_meta):
            def start():
                return p4.ACCEPT

        @p4.control
        def I(hdr, meta, std_meta):
            pass

        @p4.deparser
        def D(pkt, hdr):
            pass

        pipeline = V1Switch(
            parser=P,
            ingress=I,
            deparser=D,
        )
        self.assertEqual(pipeline.parser._p4_name, "P")
        self.assertEqual(pipeline.ingress._p4_name, "I")
        self.assertEqual(pipeline.deparser._p4_name, "D")
        self.assertIs(pipeline.headers, hdrs_t)
        self.assertIs(pipeline.metadata, meta_t)
        # Optional blocks default to None.
        self.assertIsNone(pipeline.verify_checksum)
        self.assertIsNone(pipeline.egress)
        self.assertIsNone(pipeline.compute_checksum)


if __name__ == "__main__":
    absltest.main()

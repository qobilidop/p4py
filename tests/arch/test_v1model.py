"""Tests for p4py.arch.v1model and language surface."""

import p4py.lang as p4
from p4py.arch.v1model import V1Switch, mark_to_drop, standard_metadata_t


class TestLangSurface:
    def test_parser_decorator_returns_spec(self):
        @p4.parser
        def MyParser(pkt, hdr, meta, std_meta):
            def start():
                return p4.ACCEPT

        assert MyParser._p4_kind == "parser"
        assert MyParser._p4_name == "MyParser"

    def test_parser_decorator_captures_annotations(self):
        class my_hdrs(p4.struct):
            pass

        class my_meta(p4.struct):
            pass

        @p4.parser
        def MyParser(pkt, hdr: my_hdrs, meta: my_meta, std_meta):
            def start():
                return p4.ACCEPT

        assert MyParser._p4_annotations == {"hdr": my_hdrs, "meta": my_meta}

    def test_control_decorator_returns_spec(self):
        @p4.control
        def MyIngress(hdr, meta, std_meta):
            pass

        assert MyIngress._p4_kind == "control"
        assert MyIngress._p4_name == "MyIngress"

    def test_deparser_decorator_returns_spec(self):
        @p4.deparser
        def MyDeparser(pkt, hdr):
            pass

        assert MyDeparser._p4_kind == "deparser"
        assert MyDeparser._p4_name == "MyDeparser"

    def test_sentinels_exist(self):
        assert p4.exact is not None
        assert p4.ACCEPT is not None
        assert p4.REJECT is not None
        assert p4.action is not None
        assert p4.table is not None


class TestStandardMetadata:
    def test_is_header_subclass(self):
        assert issubclass(standard_metadata_t, p4.header)

    def test_has_ingress_port(self):
        fields = dict(standard_metadata_t._p4_fields)
        assert fields["ingress_port"] == p4.bit(9)

    def test_has_egress_spec(self):
        fields = dict(standard_metadata_t._p4_fields)
        assert fields["egress_spec"] == p4.bit(9)


class TestMarkToDrop:
    def test_is_callable_sentinel(self):
        assert mark_to_drop._p4_kind == "extern"
        assert mark_to_drop._p4_name == "mark_to_drop"


class TestV1Switch:
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
        assert pipeline.parser._p4_name == "P"
        assert pipeline.ingress._p4_name == "I"
        assert pipeline.deparser._p4_name == "D"
        assert pipeline.headers is hdrs_t
        assert pipeline.metadata is meta_t
        # Optional blocks default to None.
        assert pipeline.verify_checksum is None
        assert pipeline.egress is None
        assert pipeline.compute_checksum is None

"""Tests for local variable declaration compilation."""

from absl.testing import absltest

import p4py.lang as p4
from p4py import ir as nodes
from p4py.arch.v1model import V1Switch
from p4py.compiler import compile


class ethernet_t(p4.header):
    dstAddr: p4.bit(48)
    srcAddr: p4.bit(48)
    etherType: p4.bit(16)


class headers_t(p4.struct):
    ethernet: ethernet_t


class metadata_t(p4.struct):
    pass


def _dummy_parser():
    @p4.parser
    def P(pkt, hdr: headers_t, meta: metadata_t, std_meta):
        def start():
            return p4.ACCEPT

    return P


def _dummy_deparser():
    @p4.deparser
    def D(pkt, hdr):
        pass

    return D


def _get_block(package, name):
    for entry in package.blocks:
        if entry.name == name:
            return entry.decl
    return None


class TestBoolLocalVar(absltest.TestCase):
    def test_compile_bool_local_false(self):
        """p4.bool_(False) compiles to LocalVarDecl with BoolType."""

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            x = p4.bool_(False)  # noqa: F841

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)
        ingress = _get_block(package, "ingress")

        self.assertLen(ingress.local_vars, 1)
        lv = ingress.local_vars[0]
        self.assertEqual(lv.name, "x")
        self.assertIsInstance(lv.type, nodes.BoolType)
        self.assertIsInstance(lv.init_value, nodes.BoolLiteral)
        self.assertFalse(lv.init_value.value)

    def test_compile_bool_local_true(self):
        """p4.bool_(True) compiles to LocalVarDecl with BoolType."""

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            y = p4.bool_(True)  # noqa: F841

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)
        ingress = _get_block(package, "ingress")

        self.assertLen(ingress.local_vars, 1)
        lv = ingress.local_vars[0]
        self.assertEqual(lv.name, "y")
        self.assertIsInstance(lv.type, nodes.BoolType)
        self.assertIsInstance(lv.init_value, nodes.BoolLiteral)
        self.assertTrue(lv.init_value.value)

    def test_compile_bit_local_still_works(self):
        """Existing p4.bit(W) local var pattern still works."""

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            counter = p4.bit(8)  # noqa: F841

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)
        ingress = _get_block(package, "ingress")

        self.assertLen(ingress.local_vars, 1)
        lv = ingress.local_vars[0]
        self.assertEqual(lv.name, "counter")
        self.assertIsInstance(lv.type, nodes.BitType)
        self.assertEqual(lv.type.width, 8)
        self.assertEqual(lv.init_value, 0)


class TestBoolLocalVarEmit(absltest.TestCase):
    def test_emit_bool_local_false(self):
        """Bool local var emits as 'bool x = false;'."""
        from p4py.emitter.p4 import emit

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            x = p4.bool_(False)  # noqa: F841

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)
        output = emit(package)

        self.assertIn("bool x = false;", output)

    def test_emit_bool_local_true(self):
        """Bool local var emits as 'bool y = true;'."""
        from p4py.emitter.p4 import emit

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            y = p4.bool_(True)  # noqa: F841

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)
        output = emit(package)

        self.assertIn("bool y = true;", output)

    def test_emit_bit_local_still_works(self):
        """Existing bit local var emission still works."""
        from p4py.emitter.p4 import emit

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            counter = p4.bit(8)  # noqa: F841

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)
        output = emit(package)

        self.assertIn("bit<8> counter = 0;", output)


class TestBoolLocalVarSim(absltest.TestCase):
    def test_sim_bool_local_init(self):
        """Bool local vars are initialized correctly in simulation."""
        from p4py.sim.engine import SimEngine

        @p4.control
        def MyIngress(hdr, meta, std_meta):
            x = p4.bool_(False)  # noqa: F841
            y = p4.bool_(True)  # noqa: F841

        pipeline = V1Switch(
            parser=_dummy_parser(),
            ingress=MyIngress,
            deparser=_dummy_deparser(),
        )
        package = compile(pipeline)

        engine = SimEngine(package, b"\x00" * 14, {})
        ingress = _get_block(package, "ingress")
        engine.run_control(ingress)

        self.assertEqual(engine.state.control_locals["x"], 0)
        self.assertEqual(engine.state.control_locals["y"], 1)
        self.assertEqual(engine.state.control_local_widths["x"], 1)
        self.assertEqual(engine.state.control_local_widths["y"], 1)


if __name__ == "__main__":
    absltest.main()

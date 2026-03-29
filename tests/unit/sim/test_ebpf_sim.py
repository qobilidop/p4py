"""Tests for eBPF simulation."""

from absl.testing import absltest

import p4py.lang as p4
from p4py.arch import ebpf_model
from p4py.compiler import compile
from p4py.sim import simulate


class Ethernet(p4.header):
    destination: p4.bit(48)
    source: p4.bit(48)
    protocol: p4.bit(16)


class Headers_t(p4.struct):
    ethernet: Ethernet


def _make_init_ebpf():
    """Build the init_ebpf pipeline."""

    @p4.parser
    def prs(p, headers: Headers_t):
        def start():
            p.extract(headers.ethernet)
            return p4.ACCEPT

    @p4.control
    def pipe(headers: Headers_t, pass_):
        @p4.action
        def match(act: p4.bool):
            pass_ = act  # noqa: F841

        tbl = p4.table(
            key={headers.ethernet.protocol: p4.exact},
            actions=[match, p4.NoAction],
            const_entries={
                p4.hex(0x0800): match(True),
                p4.hex(0xD000): match(False),
            },
            implementation=ebpf_model.hash_table(64),
        )

        pass_ = True  # noqa: F841
        tbl.apply()

    return ebpf_model.ebpfFilter(parser=prs, filter=pipe)


def _make_packet(ether_type: int) -> bytes:
    return b"\x00" * 12 + ether_type.to_bytes(2, "big")


class TestEbpfSimAccept(absltest.TestCase):
    def test_accept_via_const_entry(self):
        """EtherType 0x0800 matches const entry -> match(true) -> accepted."""
        program = compile(_make_init_ebpf())
        result = simulate(program, packet=_make_packet(0x0800), ingress_port=0)
        self.assertFalse(result.dropped)
        self.assertEqual(result.packet, _make_packet(0x0800))

    def test_accept_via_default_action(self):
        """EtherType 0x0000 -> no const entry match -> NoAction -> accept stays true."""
        program = compile(_make_init_ebpf())
        result = simulate(program, packet=_make_packet(0x0000), ingress_port=0)
        self.assertFalse(result.dropped)
        self.assertEqual(result.packet, _make_packet(0x0000))


class TestEbpfSimDrop(absltest.TestCase):
    def test_drop_via_const_entry(self):
        """EtherType 0xD000 matches const entry -> match(false) -> dropped."""
        program = compile(_make_init_ebpf())
        result = simulate(program, packet=_make_packet(0xD000), ingress_port=0)
        self.assertTrue(result.dropped)

    def test_drop_on_short_packet(self):
        """Packet too short for Ethernet header -> dropped."""
        program = compile(_make_init_ebpf())
        result = simulate(program, packet=b"\x00" * 9, ingress_port=0)
        self.assertTrue(result.dropped)


if __name__ == "__main__":
    absltest.main()

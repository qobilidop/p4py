"""Golden test: verify basic_routing_bmv2.p4 matches compiled output."""

import os

from p4py.backend.p4 import emit
from p4py.compiler import compile
from tests.e2e.p4_16_samples.basic_routing_bmv2.basic_routing_bmv2 import main

_HERE = os.path.dirname(__file__)
_GOLDEN_PATH = os.path.join(_HERE, "basic_routing_bmv2.p4")


class TestBasicRoutingGolden:
    def test_emitted_p4_matches_golden(self):
        program = compile(main)
        actual = emit(program)

        with open(_GOLDEN_PATH) as f:
            expected = f.read()

        assert actual == expected, (
            "Emitted P4 does not match golden file. "
            "If the change is intentional, update basic_routing_bmv2.p4."
        )

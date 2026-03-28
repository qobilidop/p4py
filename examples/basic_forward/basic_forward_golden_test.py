"""Golden test: verify basic_forward.p4 matches compiled basic_forward.py."""

import os

from examples.basic_forward.basic_forward import main
from p4py.backend.p4 import emit
from p4py.compiler import compile

_HERE = os.path.dirname(__file__)
_GOLDEN_PATH = os.path.join(_HERE, "basic_forward.p4")


class TestBasicForwardGolden:
    def test_emitted_p4_matches_golden(self):
        program = compile(main)
        actual = emit(program)

        with open(_GOLDEN_PATH) as f:
            expected = f.read()

        assert actual == expected, (
            "Emitted P4 does not match golden file. "
            "If the change is intentional, update basic_forward.p4."
        )

"""Smoke test for p4py package."""

import p4py


def test_version():
    assert p4py.__version__ == "0.0.1"

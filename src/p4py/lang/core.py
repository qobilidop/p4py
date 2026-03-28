"""core.p4 built-ins.

In P4, core.p4 defines packet_in (with extract), packet_out (with emit), and
match_kind. These are language built-ins, not externs.
"""


class _MatchKind:
    """Sentinel for match kinds."""

    def __init__(self, name: str) -> None:
        self._name = name

    def __repr__(self) -> str:
        return self._name


exact = _MatchKind("exact")

ACCEPT = "accept"
REJECT = "reject"

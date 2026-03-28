"""P4 block definitions: parser, control, deparser, and DSL sentinels."""

import inspect
import textwrap


class _Spec:
    """A captured P4 block (parser, control, or deparser)."""

    def __init__(
        self, kind: str, name: str, source: str, annotations: dict
    ) -> None:
        self._p4_kind = kind
        self._p4_name = name
        self._p4_source = source
        self._p4_annotations = annotations


def _make_decorator(kind: str):
    def decorator(func):
        source = textwrap.dedent(inspect.getsource(func))
        annotations = {
            k: v for k, v in func.__annotations__.items() if k != "return"
        }
        return _Spec(
            kind=kind, name=func.__name__, source=source, annotations=annotations
        )

    return decorator


parser = _make_decorator("parser")
control = _make_decorator("control")
deparser = _make_decorator("deparser")


class _Sentinel:
    """A sentinel object recognized by the AST parser."""

    def __init__(self, kind: str, name: str) -> None:
        self._p4_kind = kind
        self._p4_name = name

    def __repr__(self) -> str:
        return self._p4_name


action = _Sentinel("decorator", "action")
table = _Sentinel("builtin", "table")

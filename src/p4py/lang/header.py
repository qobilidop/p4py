"""P4 header base class."""

from __future__ import annotations

from p4py.lang.bit import BitType


class header:
    """Base class for P4 header types.

    Subclass and annotate fields with bit(W):

        class ethernet_t(header):
            dstAddr: bit(48)
            srcAddr: bit(48)
            etherType: bit(16)
    """

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        fields: list[tuple[str, BitType]] = []
        for name, ann in cls.__annotations__.items():
            if not isinstance(ann, BitType):
                raise TypeError(
                    f"Header field '{name}' must be annotated with bit(W), got {ann!r}"
                )
            fields.append((name, ann))
        if not fields:
            raise TypeError(f"Header '{cls.__name__}' must have at least one field")
        cls._p4_name = cls.__name__
        cls._p4_fields = tuple(fields)
        cls._p4_bit_width = sum(f.width for _, f in fields)

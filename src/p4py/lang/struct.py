"""P4 struct base class."""

from __future__ import annotations

from p4py.lang.header import header


class struct:
    """Base class for P4 struct types.

    Subclass and annotate members with header subclasses:

        class headers_t(struct):
            ethernet: ethernet_t
            ipv4: ipv4_t

    Empty structs (e.g., metadata) are allowed.
    """

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        members: list[tuple[str, type]] = []
        for name, ann in cls.__annotations__.items():
            if not (isinstance(ann, type) and issubclass(ann, header)):
                raise TypeError(
                    f"Struct member '{name}' must be a header subclass, got {ann!r}"
                )
            members.append((name, ann))
        cls._p4_name = cls.__name__
        cls._p4_members = tuple(members)

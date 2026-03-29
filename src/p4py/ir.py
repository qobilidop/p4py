"""P4 IR node types.

All nodes are frozen dataclasses. They form the canonical representation of a
P4Py program that emitters and the simulator operate on.
"""

from __future__ import annotations

from dataclasses import dataclass

# --- Types ---


@dataclass(frozen=True)
class BitType:
    width: int


@dataclass(frozen=True)
class BoolType:
    pass


@dataclass(frozen=True)
class HeaderField:
    name: str
    type: BitType


@dataclass(frozen=True)
class HeaderType:
    name: str
    fields: tuple[HeaderField, ...]


@dataclass(frozen=True)
class StructMember:
    name: str
    type: BitType | str  # BitType for bit<W> fields, str for header type name


@dataclass(frozen=True)
class StructType:
    name: str
    members: tuple[StructMember, ...]


# --- Expressions ---


@dataclass(frozen=True)
class FieldAccess:
    path: tuple[str, ...]


@dataclass(frozen=True)
class IntLiteral:
    value: int
    width: int | None = None
    hex: bool = False


@dataclass(frozen=True)
class BoolLiteral:
    value: bool


@dataclass(frozen=True)
class ArithOp:
    op: str  # '+' or '-'
    left: Expression
    right: Expression


@dataclass(frozen=True)
class IsValid:
    header_ref: FieldAccess


@dataclass(frozen=True)
class ListExpression:
    elements: tuple[Expression, ...]


@dataclass(frozen=True)
class Masked:
    value: Expression
    mask: Expression


@dataclass(frozen=True)
class Wildcard:
    pass


Expression = (
    FieldAccess
    | IntLiteral
    | BoolLiteral
    | ArithOp
    | IsValid
    | ListExpression
    | Masked
    | Wildcard
)


# --- Statements ---


@dataclass(frozen=True)
class Assignment:
    target: FieldAccess
    value: Expression


@dataclass(frozen=True)
class MethodCall:
    object: FieldAccess
    method: str
    args: tuple[Expression, ...]


@dataclass(frozen=True)
class FunctionCall:
    name: str
    args: tuple[Expression, ...]


@dataclass(frozen=True)
class ActionCall:
    name: str
    args: tuple[Expression, ...]


@dataclass(frozen=True)
class TableApply:
    table_name: str


@dataclass(frozen=True)
class IfElse:
    condition: IsValid  # Conditions restricted to IsValid only (hdr.x.isValid())
    then_body: tuple[Statement, ...]
    else_body: tuple[Statement, ...]


@dataclass(frozen=True)
class SwitchActionCase:
    action_name: str
    body: tuple[Statement, ...]


@dataclass(frozen=True)
class SwitchAction:
    table_name: str
    cases: tuple[SwitchActionCase, ...]


@dataclass(frozen=True)
class ConstEntry:
    values: tuple[Expression, ...]
    action_name: str
    action_args: tuple[Expression, ...]


Statement = (
    Assignment
    | MethodCall
    | FunctionCall
    | ActionCall
    | TableApply
    | IfElse
    | SwitchAction
)


# --- Parser ---


@dataclass(frozen=True)
class Transition:
    next_state: str


@dataclass(frozen=True)
class SelectCase:
    value: int | None  # None = default
    next_state: str


@dataclass(frozen=True)
class TransitionSelect:
    field: FieldAccess
    cases: tuple[SelectCase, ...]


@dataclass(frozen=True)
class ParserState:
    name: str
    body: tuple[Statement, ...]
    transition: Transition | TransitionSelect


@dataclass(frozen=True)
class ParserDecl:
    name: str
    states: tuple[ParserState, ...]
    param_names: tuple[str, ...] = ()


# --- Actions and Tables ---


@dataclass(frozen=True)
class ActionParam:
    name: str
    type: BitType | BoolType


@dataclass(frozen=True)
class ActionDecl:
    name: str
    params: tuple[ActionParam, ...]
    body: tuple[Statement, ...]


@dataclass(frozen=True)
class TableKey:
    field: FieldAccess
    match_kind: str


@dataclass(frozen=True)
class TableDecl:
    name: str
    keys: tuple[TableKey, ...]
    actions: tuple[str, ...]
    default_action: str
    default_action_args: tuple[Expression, ...]
    size: int | None = None
    const_entries: tuple[ConstEntry, ...] = ()
    implementation: str | None = None


# --- Control ---


@dataclass(frozen=True)
class ControlDecl:
    name: str
    actions: tuple[ActionDecl, ...]
    tables: tuple[TableDecl, ...]
    apply_body: tuple[Statement, ...]
    param_names: tuple[str, ...] = ()


# --- Deparser ---


@dataclass(frozen=True)
class DeparserDecl:
    name: str
    emit_order: tuple[FieldAccess, ...]
    param_names: tuple[str, ...] = ()


# --- Package ---


@dataclass(frozen=True)
class BlockEntry:
    name: str
    kind: str  # "parser", "control", "deparser"
    decl: ParserDecl | ControlDecl | DeparserDecl


@dataclass(frozen=True)
class Package:
    arch: object  # Architecture instance (typed as object to avoid circular import)
    headers: tuple[HeaderType, ...]
    structs: tuple[StructType, ...]
    blocks: tuple[BlockEntry, ...]

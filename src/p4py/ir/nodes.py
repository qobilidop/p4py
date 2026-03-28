"""P4 IR node types.

All nodes are frozen dataclasses. They form the canonical representation of a
P4Mini program that backends and the simulator operate on.
"""

from __future__ import annotations

from dataclasses import dataclass

# --- Types ---


@dataclass(frozen=True)
class BitType:
    width: int


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


@dataclass(frozen=True)
class ArithOp:
    op: str  # '+' or '-'
    left: Expression
    right: Expression


@dataclass(frozen=True)
class IsValid:
    header_ref: FieldAccess


Expression = FieldAccess | IntLiteral | ArithOp | IsValid


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
    condition: IsValid  # P4Mini restricts conditions to IsValid only (hdr.x.isValid())
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


# --- Actions and Tables ---


@dataclass(frozen=True)
class ActionParam:
    name: str
    type: BitType


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


# --- Control ---


@dataclass(frozen=True)
class ControlDecl:
    name: str
    actions: tuple[ActionDecl, ...]
    tables: tuple[TableDecl, ...]
    apply_body: tuple[Statement, ...]


# --- Deparser ---


@dataclass(frozen=True)
class DeparserDecl:
    name: str
    emit_order: tuple[FieldAccess, ...]


# --- Program ---


@dataclass(frozen=True)
class Program:
    headers: tuple[HeaderType, ...]
    structs: tuple[StructType, ...]
    parser: ParserDecl
    ingress: ControlDecl
    deparser: DeparserDecl

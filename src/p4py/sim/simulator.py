"""P4Mini packet simulator.

Interprets IR nodes to process packets: parse headers from a byte buffer,
execute ingress control logic with table lookups, and deparse headers back
to bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from p4py.ir import nodes

# Drop port sentinel — standard_metadata.egress_spec is set to this value by
# mark_to_drop in v1model. 511 = 0x1FF = all 1s in 9 bits.
_DROP_PORT = 511


@dataclass
class SimResult:
    """Result of simulating a packet."""

    packet: bytes | None
    egress_port: int
    dropped: bool


@dataclass
class _HeaderInstance:
    """Runtime state of a parsed header."""

    type_info: nodes.HeaderType
    valid: bool = False
    fields: dict[str, int] = field(default_factory=dict)


@dataclass
class _SimState:
    """Mutable simulation state for one packet."""

    packet_bytes: bytearray
    cursor: int
    headers: dict[str, _HeaderInstance]
    metadata: dict[str, int]
    std_meta: dict[str, int]
    program: nodes.Program


def simulate(
    program: nodes.Program,
    packet: bytes,
    ingress_port: int,
    table_entries: dict[str, list[dict]] | None = None,
) -> SimResult:
    """Simulate a packet through a P4Mini program."""
    if table_entries is None:
        table_entries = {}

    # Initialize header instances.
    headers: dict[str, _HeaderInstance] = {}
    header_types = {h.name: h for h in program.headers}
    for s in program.structs:
        if s.name.endswith("_t") and s.members:
            for member in s.members:
                headers[member.name] = _HeaderInstance(
                    type_info=header_types[member.header_type_name]
                )

    state = _SimState(
        packet_bytes=bytearray(packet),
        cursor=0,
        headers=headers,
        metadata={},
        std_meta={"ingress_port": ingress_port, "egress_spec": 0},
        program=program,
    )

    _run_parser(state, program.parser)
    _run_control(state, program.ingress, table_entries)

    if state.std_meta["egress_spec"] == _DROP_PORT:
        return SimResult(packet=None, egress_port=_DROP_PORT, dropped=True)

    output = _run_deparser(state, program.deparser)
    return SimResult(
        packet=bytes(output),
        egress_port=state.std_meta["egress_spec"],
        dropped=False,
    )


def _run_parser(state: _SimState, parser: nodes.ParserDecl) -> None:
    """Execute the parser state machine."""
    states = {s.name: s for s in parser.states}
    current = parser.states[0].name  # Start state is always first.

    while current not in ("accept", "reject"):
        parser_state = states[current]
        for stmt in parser_state.body:
            _exec_statement(state, stmt, {})

        transition = parser_state.transition
        if isinstance(transition, nodes.Transition):
            current = transition.next_state
        elif isinstance(transition, nodes.TransitionSelect):
            field_val = _eval_expression(state, transition.field, {})
            current = _match_select(transition.cases, field_val)


def _match_select(cases: tuple[nodes.SelectCase, ...], value: int) -> str:
    """Find the matching case in a transition select."""
    default = None
    for case in cases:
        if case.value is None:
            default = case.next_state
        elif case.value == value:
            return case.next_state
    if default is not None:
        return default
    return "reject"


def _run_control(
    state: _SimState,
    control: nodes.ControlDecl,
    table_entries: dict[str, list[dict]],
) -> None:
    """Execute a control block."""
    actions = {a.name: a for a in control.actions}
    tables = {t.name: t for t in control.tables}
    ctx = _ControlContext(actions=actions, tables=tables, entries=table_entries)

    for stmt in control.apply_body:
        _exec_control_statement(state, stmt, ctx)


@dataclass
class _ControlContext:
    actions: dict[str, nodes.ActionDecl]
    tables: dict[str, nodes.TableDecl]
    entries: dict[str, list[dict]]


def _exec_control_statement(
    state: _SimState, stmt: nodes.Statement, ctx: _ControlContext
) -> None:
    """Execute a statement in a control apply block."""
    if isinstance(stmt, nodes.TableApply):
        _exec_table_apply(state, stmt.table_name, ctx)
    elif isinstance(stmt, nodes.IfElse):
        if _eval_is_valid(state, stmt.condition):
            for s in stmt.then_body:
                _exec_control_statement(state, s, ctx)
        else:
            for s in stmt.else_body:
                _exec_control_statement(state, s, ctx)
    elif isinstance(stmt, nodes.FunctionCall):
        _exec_action_by_name(state, stmt.name, {}, ctx)
    else:
        raise ValueError(f"Unsupported control statement: {stmt}")


def _exec_table_apply(state: _SimState, table_name: str, ctx: _ControlContext) -> None:
    """Look up a table entry and execute the matching action."""
    table = ctx.tables[table_name]
    entries = ctx.entries.get(table_name, [])

    # Build the lookup key from current header values.
    lookup_key = {}
    for table_key in table.keys:
        field_path = ".".join(table_key.field.path)
        lookup_key[field_path] = _eval_expression(state, table_key.field, {})

    # Find matching entry.
    for entry in entries:
        if all(entry["key"].get(k) == v for k, v in lookup_key.items()):
            action_name = entry["action"]
            action_args = entry.get("args", {})
            _exec_action_by_name(state, action_name, action_args, ctx)
            return

    # No match — execute default action.
    _exec_action_by_name(state, table.default_action, {}, ctx)


def _exec_action_by_name(
    state: _SimState,
    action_name: str,
    args: dict[str, int],
    ctx: _ControlContext,
) -> None:
    """Execute a named action with given arguments."""
    action = ctx.actions[action_name]
    # Build local bindings from action params.
    local_bindings: dict[str, int] = {}
    for param in action.params:
        local_bindings[param.name] = args[param.name]
    for stmt in action.body:
        _exec_statement(state, stmt, local_bindings)


def _exec_statement(
    state: _SimState, stmt: nodes.Statement, locals_: dict[str, int]
) -> None:
    """Execute a single statement."""
    if isinstance(stmt, nodes.MethodCall):
        if stmt.method == "extract":
            _exec_extract(state, stmt.args[0])
        else:
            raise ValueError(f"Unknown method: {stmt.method}")
    elif isinstance(stmt, nodes.FunctionCall):
        if stmt.name == "mark_to_drop":
            state.std_meta["egress_spec"] = _DROP_PORT
        else:
            raise ValueError(f"Unknown function: {stmt.name}")
    elif isinstance(stmt, nodes.Assignment):
        value = _eval_expression(state, stmt.value, locals_)
        _set_field(state, stmt.target, value)
    else:
        raise ValueError(f"Unsupported statement in action: {stmt}")


def _exec_extract(state: _SimState, header_ref: nodes.Expression) -> None:
    """Extract a header from the packet byte buffer."""
    if not isinstance(header_ref, nodes.FieldAccess):
        raise ValueError(f"Expected FieldAccess, got {header_ref}")
    # header_ref.path is like ("hdr", "ethernet")
    header_name = header_ref.path[-1]
    hdr = state.headers[header_name]
    hdr.valid = True

    bit_offset = 0
    for field_info in hdr.type_info.fields:
        width = field_info.type.width
        value = _read_bits(state.packet_bytes, state.cursor + bit_offset, width)
        hdr.fields[field_info.name] = value
        bit_offset += width

    state.cursor += bit_offset


def _read_bits(data: bytearray, bit_offset: int, width: int) -> int:
    """Read `width` bits from `data` starting at `bit_offset`."""
    value = 0
    for i in range(width):
        byte_idx = (bit_offset + i) // 8
        bit_idx = 7 - ((bit_offset + i) % 8)
        if byte_idx < len(data):
            value = (value << 1) | ((data[byte_idx] >> bit_idx) & 1)
        else:
            value = value << 1
    return value


def _write_bits(data: bytearray, bit_offset: int, width: int, value: int) -> None:
    """Write `width` bits of `value` into `data` starting at `bit_offset`."""
    for i in range(width):
        byte_idx = (bit_offset + i) // 8
        bit_idx = 7 - ((bit_offset + i) % 8)
        bit_val = (value >> (width - 1 - i)) & 1
        if bit_val:
            data[byte_idx] |= 1 << bit_idx
        else:
            data[byte_idx] &= ~(1 << bit_idx)


def _eval_expression(
    state: _SimState, expr: nodes.Expression, locals_: dict[str, int]
) -> int:
    """Evaluate an expression to an integer value."""
    if isinstance(expr, nodes.IntLiteral):
        return expr.value
    if isinstance(expr, nodes.FieldAccess):
        return _get_field(state, expr, locals_)
    if isinstance(expr, nodes.ArithOp):
        left = _eval_expression(state, expr.left, locals_)
        right = _eval_expression(state, expr.right, locals_)
        if expr.op == "+":
            return left + right
        if expr.op == "-":
            return left - right
        raise ValueError(f"Unknown op: {expr.op}")
    raise ValueError(f"Cannot evaluate: {expr}")


def _eval_is_valid(state: _SimState, iv: nodes.IsValid) -> bool:
    """Check if a header is valid."""
    header_name = iv.header_ref.path[-1]
    return state.headers[header_name].valid


def _get_field(state: _SimState, fa: nodes.FieldAccess, locals_: dict[str, int]) -> int:
    """Read a field value."""
    path = fa.path
    # Local variable (action parameter).
    if len(path) == 1:
        return locals_[path[0]]
    # std_meta.field
    if path[0] == "std_meta":
        return state.std_meta[path[1]]
    # hdr.header.field
    if path[0] == "hdr" and len(path) == 3:
        return state.headers[path[1]].fields[path[2]]
    raise ValueError(f"Cannot read field: {'.'.join(path)}")


def _set_field(state: _SimState, fa: nodes.FieldAccess, value: int) -> None:
    """Write a field value."""
    path = fa.path
    if path[0] == "std_meta":
        state.std_meta[path[1]] = value
    elif path[0] == "hdr" and len(path) == 3:
        state.headers[path[1]].fields[path[2]] = value
    else:
        raise ValueError(f"Cannot write field: {'.'.join(path)}")


def _run_deparser(state: _SimState, deparser: nodes.DeparserDecl) -> bytearray:
    """Deparse headers back to bytes, followed by remaining payload."""
    output = bytearray()
    for field_ref in deparser.emit_order:
        header_name = field_ref.path[-1]
        hdr = state.headers[header_name]
        if not hdr.valid:
            continue
        for field_info in hdr.type_info.fields:
            width = field_info.type.width
            value = hdr.fields[field_info.name]
            # Append bits, padded to byte boundary per header.
            _append_bits(output, width, value)

    # Append remaining payload (bytes after parsed headers).
    payload_start = state.cursor // 8
    output.extend(state.packet_bytes[payload_start:])
    return output


def _append_bits(output: bytearray, width: int, value: int) -> None:
    """Append `width` bits of `value` to the output buffer."""
    # For simplicity, accumulate into existing output byte-by-byte.
    bit_offset = len(output) * 8
    # Extend output to have enough bytes.
    needed_bytes = (bit_offset + width + 7) // 8
    while len(output) < needed_bytes:
        output.append(0)
    _write_bits(output, bit_offset, width, value)

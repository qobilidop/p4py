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

    # Initialize header instances and metadata fields from struct definitions.
    headers: dict[str, _HeaderInstance] = {}
    metadata: dict[str, int] = {}
    header_types = {h.name: h for h in program.headers}
    struct_types = {s.name: s for s in program.structs}
    for s in program.structs:
        for member in s.members:
            if isinstance(member.type, nodes.BitType):
                # Metadata field — initialize to zero.
                metadata[member.name] = 0
            elif isinstance(member.type, str) and member.type in header_types:
                headers[member.name] = _HeaderInstance(
                    type_info=header_types[member.type]
                )
            elif isinstance(member.type, str) and member.type in struct_types:
                # Nested struct — expand inner fields with dotted prefix.
                inner = struct_types[member.type]
                for inner_member in inner.members:
                    if isinstance(inner_member.type, nodes.BitType):
                        metadata[f"{member.name}.{inner_member.name}"] = 0

    state = _SimState(
        packet_bytes=bytearray(packet),
        cursor=0,
        headers=headers,
        metadata=metadata,
        std_meta={"ingress_port": ingress_port, "egress_spec": 0},
        program=program,
    )

    _run_parser(state, program.parser)

    if program.verify_checksum is not None:
        _run_control(state, program.verify_checksum, table_entries)

    _run_control(state, program.ingress, table_entries)

    if state.std_meta["egress_spec"] == _DROP_PORT:
        return SimResult(packet=None, egress_port=_DROP_PORT, dropped=True)

    if program.egress is not None:
        _run_control(state, program.egress, table_entries)

    if program.compute_checksum is not None:
        _run_control(state, program.compute_checksum, table_entries)

    output = _run_deparser(state, program.deparser)
    return SimResult(
        packet=bytes(output),
        egress_port=state.std_meta["egress_spec"],
        dropped=False,
    )


def _run_parser(state: _SimState, parser: nodes.ParserDecl) -> str:
    """Execute the parser state machine. Returns terminal state ('accept' or 'reject')."""
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

    return current


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
    elif isinstance(stmt, nodes.SwitchAction):
        action_run = _exec_table_apply(state, stmt.table_name, ctx)
        for case in stmt.cases:
            if case.action_name == action_run:
                for s in case.body:
                    _exec_control_statement(state, s, ctx)
                break
    elif isinstance(stmt, nodes.FunctionCall):
        _exec_action_by_name(state, stmt.name, {}, ctx)
    elif isinstance(stmt, nodes.ChecksumVerify):
        _exec_checksum_verify(state, stmt)
    elif isinstance(stmt, nodes.ChecksumUpdate):
        _exec_checksum_update(state, stmt)
    else:
        raise ValueError(f"Unsupported control statement: {stmt}")


def _exec_table_apply(state: _SimState, table_name: str, ctx: _ControlContext) -> str:
    """Look up a table entry, execute the matching action, return action name."""
    table = ctx.tables[table_name]
    entries = ctx.entries.get(table_name, [])

    # Build the lookup key, match kind, and field width maps.
    lookup_key = {}
    match_kinds = {}
    field_widths = {}
    for table_key in table.keys:
        field_path = ".".join(table_key.field.path)
        lookup_key[field_path] = _eval_expression(state, table_key.field, {})
        match_kinds[field_path] = table_key.match_kind
        field_widths[field_path] = _resolve_field_width(state, table_key.field)

    # Find matching entry (longest prefix match for LPM fields).
    best_match = None
    best_prefix_len = -1
    for entry in entries:
        if _entry_matches(entry, lookup_key, match_kinds, field_widths):
            # For LPM, pick the entry with the longest prefix.
            prefix_total = sum(
                entry.get("prefix_len", {}).get(k, 0) for k in lookup_key
            )
            if prefix_total > best_prefix_len:
                best_match = entry
                best_prefix_len = prefix_total

    if best_match is not None:
        action_name = best_match["action"]
        _exec_action_by_name(state, action_name, best_match.get("args", {}), ctx)
        return action_name

    # No match — execute default action (no-op if none specified).
    if table.default_action:
        _exec_action_by_name(state, table.default_action, {}, ctx)
    return table.default_action


def _resolve_struct_field_width(
    s: nodes.StructType,
    remaining: list[str],
    struct_types: dict[str, nodes.StructType],
) -> int | None:
    """Walk a struct chain to resolve a field's bit width."""
    for member in s.members:
        if member.name == remaining[0]:
            if len(remaining) == 1 and isinstance(member.type, nodes.BitType):
                return member.type.width
            if len(remaining) > 1 and isinstance(member.type, str):
                inner = struct_types.get(member.type)
                if inner is not None:
                    return _resolve_struct_field_width(
                        inner, remaining[1:], struct_types
                    )
    return None


def _resolve_field_width(state: _SimState, field: nodes.FieldAccess) -> int:
    """Look up the bit width of a header or metadata field."""
    path = field.path
    # hdr.header.field → look up from header type info
    if path[0] == "hdr" and len(path) == 3:
        header_inst = state.headers[path[1]]
        for hf in header_inst.type_info.fields:
            if hf.name == path[2]:
                return hf.type.width
    # meta.field or meta.struct.field → look up from program struct definitions
    if path[0] == "meta" and len(path) >= 2:
        # For nested paths like meta.ingress_metadata.vrf, walk the struct chain.
        struct_types = {s.name: s for s in state.program.structs}
        # Start from all top-level structs and try to resolve.
        remaining = list(path[1:])
        for s in state.program.structs:
            result = _resolve_struct_field_width(s, remaining, struct_types)
            if result is not None:
                return result
    # std_meta.field → look up from standard_metadata_t definition
    if path[0] == "std_meta" and len(path) == 2:
        from p4py.arch.v1model import standard_metadata_t

        for name, bit_type in standard_metadata_t._p4_fields:
            if name == path[1]:
                return bit_type.width
    raise ValueError(f"Cannot resolve field width: {field}")


def _entry_matches(
    entry: dict,
    lookup_key: dict[str, int],
    match_kinds: dict[str, str],
    field_widths: dict[str, int],
) -> bool:
    """Check if a table entry matches the lookup key."""
    for field_path, value in lookup_key.items():
        entry_value = entry["key"].get(field_path)
        if entry_value is None:
            return False
        kind = match_kinds.get(field_path, "exact")
        if kind == "exact":
            if entry_value != value:
                return False
        elif kind == "lpm":
            prefix_len = entry.get("prefix_len", {}).get(field_path, 0)
            width = field_widths[field_path]
            shift = width - prefix_len
            if (value >> shift) != (entry_value >> shift):
                return False
    return True


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

    # Check if enough bits remain in the packet for this header.
    total_bits = sum(f.type.width for f in hdr.type_info.fields)
    available_bits = (len(state.packet_bytes) * 8) - state.cursor
    if available_bits < total_bits:
        # Not enough data — header stays invalid (extract fails).
        return

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


def _compute_csum16(field_values: list[tuple[int, int]]) -> int:
    """Compute 16-bit ones' complement checksum (RFC 1071).

    Args:
        field_values: List of (value, width_in_bits) pairs.
    """
    # Concatenate all fields into a single bit string, then sum 16-bit words.
    total_bits = 0
    combined = 0
    for value, width in field_values:
        combined = (combined << width) | (value & ((1 << width) - 1))
        total_bits += width

    # Pad to 16-bit boundary.
    if total_bits % 16:
        pad = 16 - (total_bits % 16)
        combined <<= pad
        total_bits += pad

    # Sum 16-bit words.
    total = 0
    num_words = total_bits // 16
    for i in range(num_words):
        shift = (num_words - 1 - i) * 16
        word = (combined >> shift) & 0xFFFF
        total += word

    # Fold carry bits.
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def _exec_checksum_verify(state: _SimState, stmt: nodes.ChecksumVerify) -> None:
    """Execute verify_checksum — currently a no-op (verification only)."""
    # In a real switch, this would mark the packet for drop on mismatch.
    # For simulation, we skip verification — update_checksum is what matters.
    pass


def _exec_checksum_update(state: _SimState, stmt: nodes.ChecksumUpdate) -> None:
    """Execute update_checksum — recompute and write back the checksum."""
    cond_val = _eval_expression(state, stmt.condition, {})
    if not cond_val:
        return

    field_values: list[tuple[int, int]] = []
    for fa in stmt.data:
        value = _eval_expression(state, fa, {})
        width = _resolve_field_width(state, fa)
        field_values.append((value, width))

    checksum = _compute_csum16(field_values)
    _set_field(state, stmt.checksum, checksum)


def _eval_expression(
    state: _SimState, expr: nodes.Expression, locals_: dict[str, int]
) -> int:
    """Evaluate an expression to an integer value."""
    if isinstance(expr, nodes.BoolLiteral):
        return int(expr.value)
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
    if isinstance(expr, nodes.IsValid):
        return int(_eval_is_valid(state, expr))
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
    # meta.field or meta.struct.field
    if path[0] == "meta":
        key = ".".join(path[1:])
        return state.metadata[key]
    # hdr.header.field
    if path[0] == "hdr" and len(path) == 3:
        return state.headers[path[1]].fields.get(path[2], 0)
    raise ValueError(f"Cannot read field: {'.'.join(path)}")


def _set_field(state: _SimState, fa: nodes.FieldAccess, value: int) -> None:
    """Write a field value."""
    path = fa.path
    if path[0] == "std_meta":
        state.std_meta[path[1]] = value
    elif path[0] == "meta":
        key = ".".join(path[1:])
        state.metadata[key] = value
    elif path[0] == "hdr" and len(path) == 3:
        state.headers[path[1]].fields[path[2]] = value
    else:
        raise ValueError(f"Cannot write field: {'.'.join(path)}")


def _run_deparser(state: _SimState, deparser: nodes.DeparserDecl) -> bytearray:
    """Deparse headers back to bytes, followed by remaining payload."""
    output = bytearray()
    bit_offset = 0
    for field_ref in deparser.emit_order:
        header_name = field_ref.path[-1]
        hdr = state.headers[header_name]
        if not hdr.valid:
            continue
        for field_info in hdr.type_info.fields:
            width = field_info.type.width
            value = hdr.fields[field_info.name]
            needed_bytes = (bit_offset + width + 7) // 8
            while len(output) < needed_bytes:
                output.append(0)
            _write_bits(output, bit_offset, width, value)
            bit_offset += width

    # Append remaining payload (bytes after parsed headers).
    payload_start = state.cursor // 8
    output.extend(state.packet_bytes[payload_start:])
    return output

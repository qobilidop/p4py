"""Shared simulation engine.

Provides the execution primitives for parsing, control, and deparsing.
Architecture-specific pipeline orchestration lives in each arch module.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from p4py import ir


@dataclass
class _HeaderInstance:
    """Runtime state of a parsed header."""

    type_info: ir.HeaderType
    valid: bool = False
    fields: dict[str, int] = field(default_factory=dict)


@dataclass
class _SimState:
    """Mutable simulation state for one packet."""

    packet_bytes: bytearray
    cursor: int
    headers: dict[str, _HeaderInstance]
    metadata: dict[str, int]
    metadata_widths: dict[str, int]
    program: object  # Package
    control_locals: dict[str, int] = field(default_factory=dict)
    control_local_widths: dict[str, int] = field(default_factory=dict)


def init_state(
    package: ir.Package,
) -> tuple[dict[str, _HeaderInstance], dict[str, int], dict[str, int]]:
    """Initialize headers, metadata, and metadata_widths from a Package."""
    headers: dict[str, _HeaderInstance] = {}
    metadata: dict[str, int] = {}
    metadata_widths: dict[str, int] = {}
    header_types = {h.name: h for h in package.headers}
    struct_types = {s.name: s for s in package.structs}

    # Build a width map for named types (typedefs, newtypes, enums).
    named_type_widths: dict[str, int] = {}
    for decl in package.declarations:
        if isinstance(decl, (ir.TypedefDecl, ir.NewtypeDecl)):
            named_type_widths[decl.name] = decl.type.width
        elif isinstance(decl, ir.EnumDecl):
            named_type_widths[decl.name] = decl.underlying_type.width

    def _member_width(member_type):
        """Return the bit width for a member type, or None if not scalar."""
        if isinstance(member_type, ir.BitType):
            return member_type.width
        if isinstance(member_type, ir.BoolType):
            return 1
        if isinstance(member_type, str) and member_type in named_type_widths:
            return named_type_widths[member_type]
        return None

    for s in package.structs:
        for member in s.members:
            width = _member_width(member.type)
            if width is not None:
                metadata[member.name] = 0
                metadata_widths[member.name] = width
            elif isinstance(member.type, str) and member.type in header_types:
                headers[member.name] = _HeaderInstance(
                    type_info=header_types[member.type]
                )
            elif isinstance(member.type, str) and member.type in struct_types:
                inner = struct_types[member.type]
                for inner_member in inner.members:
                    inner_width = _member_width(inner_member.type)
                    if inner_width is not None:
                        key = f"{member.name}.{inner_member.name}"
                        metadata[key] = 0
                        metadata_widths[key] = inner_width
    return headers, metadata, metadata_widths


class SimEngine:
    """Shared simulation engine used by all architectures."""

    def __init__(
        self,
        package: ir.Package,
        packet: bytes,
        table_entries: dict[str, list[dict]],
    ) -> None:
        headers, metadata, metadata_widths = init_state(package)
        self.state = _SimState(
            packet_bytes=bytearray(packet),
            cursor=0,
            headers=headers,
            metadata=metadata,
            metadata_widths=metadata_widths,
            program=package,
        )
        self._table_entries = table_entries
        self._externs: dict[str, object] = {}

    def register_extern(self, name: str, handler) -> None:
        """Register an extern function handler."""
        self._externs[name] = handler

    def run_parser(self, parser_decl: ir.ParserDecl) -> str:
        """Execute the parser state machine. Returns terminal state."""
        return _run_parser(self.state, parser_decl, self._externs)

    def run_control(self, control_decl: ir.ControlDecl) -> None:
        """Execute a control block."""
        _run_control(self.state, control_decl, self._table_entries, self._externs)

    def run_deparser(self, deparser_decl: ir.DeparserDecl) -> bytes:
        """Deparse headers back to bytes."""
        return bytes(_run_deparser(self.state, deparser_decl))

    def eval_expression(self, expr: ir.Expression) -> int:
        """Evaluate an expression to an integer value."""
        return _eval_expression(self.state, expr, {})

    def resolve_field_width(self, field_access: ir.FieldAccess) -> int:
        """Look up the bit width of a field."""
        return _resolve_field_width(self.state, field_access)

    def set_field(self, field_access: ir.FieldAccess, value: int) -> None:
        """Write a field value."""
        _set_field(self.state, field_access, value)


# ---------------------------------------------------------------------------
# Internal execution functions
# ---------------------------------------------------------------------------


def _run_parser(
    state: _SimState,
    parser: ir.ParserDecl,
    externs: dict[str, object],
) -> str:
    """Execute the parser state machine. Returns terminal state."""
    states = {s.name: s for s in parser.states}
    current = parser.states[0].name

    while current not in ("accept", "reject"):
        parser_state = states[current]
        for stmt in parser_state.body:
            _exec_statement(state, stmt, {}, externs)

        transition = parser_state.transition
        if isinstance(transition, ir.Transition):
            current = transition.next_state
        elif isinstance(transition, ir.TransitionSelect):
            field_val = _eval_expression(state, transition.field, {})
            current = _match_select(state, transition.cases, field_val)

    return current


def _match_select(
    state: _SimState, cases: tuple[ir.SelectCase, ...], value: int
) -> str:
    """Find the matching case in a transition select."""
    default = None
    for case in cases:
        if case.value is None:
            default = case.next_state
        else:
            case_value = case.value
            if isinstance(case_value, ir.ConstRef):
                case_value = _eval_expression(state, case_value, {})
            if case_value == value:
                return case.next_state
    if default is not None:
        return default
    return "reject"


def _run_control(
    state: _SimState,
    control: ir.ControlDecl,
    table_entries: dict[str, list[dict]],
    externs: dict[str, object],
) -> None:
    """Execute a control block."""
    actions = {a.name: a for a in control.actions}
    tables = {t.name: t for t in control.tables}
    ctx = _ControlContext(
        actions=actions,
        tables=tables,
        entries=table_entries,
        externs=externs,
    )

    # Initialize control-local variables
    for lv in control.local_vars:
        state.control_locals[lv.name] = lv.init_value
        state.control_local_widths[lv.name] = lv.type.width

    for stmt in control.apply_body:
        _exec_control_statement(state, stmt, ctx)


@dataclass
class _ControlContext:
    actions: dict[str, ir.ActionDecl]
    tables: dict[str, ir.TableDecl]
    entries: dict[str, list[dict]]
    externs: dict[str, object]


def _exec_control_statement(
    state: _SimState, stmt: ir.Statement, ctx: _ControlContext
) -> None:
    """Execute a statement in a control apply block."""
    if isinstance(stmt, ir.TableApply):
        _exec_table_apply(state, stmt.table_name, ctx)
    elif isinstance(stmt, ir.IfElse):
        cond_val = _eval_expression(state, stmt.condition, {})
        if cond_val:
            for s in stmt.then_body:
                _exec_control_statement(state, s, ctx)
        else:
            for s in stmt.else_body:
                _exec_control_statement(state, s, ctx)
    elif isinstance(stmt, ir.SwitchAction):
        action_run = _exec_table_apply(state, stmt.table_name, ctx)
        for case in stmt.cases:
            if case.action_name == action_run:
                for s in case.body:
                    _exec_control_statement(state, s, ctx)
                break
    elif isinstance(stmt, ir.FunctionCall):
        if stmt.name in ctx.externs:
            ctx.externs[stmt.name](stmt)
        else:
            _exec_action_by_name(state, stmt.name, {}, ctx)
    elif isinstance(stmt, ir.MethodCall) and stmt.method == "apply":
        # Sub-control apply: look up from package and execute
        control_name = stmt.object.path[0]
        for sc in state.program.sub_controls:
            if sc.name == control_name:
                _run_control(state, sc, ctx.entries, ctx.externs)
                break
    elif isinstance(stmt, ir.Assignment):
        value = _eval_expression(state, stmt.value, {})
        _set_field(state, stmt.target, value)
    else:
        raise ValueError(f"Unsupported control statement: {stmt}")


def _exec_table_apply(state: _SimState, table_name: str, ctx: _ControlContext) -> str:
    """Look up a table entry, execute the matching action, return action name."""
    table = ctx.tables[table_name]
    entries = ctx.entries.get(table_name, [])

    lookup_key = {}
    match_kinds = {}
    field_widths = {}
    for table_key in table.keys:
        if isinstance(table_key.field, ir.IsValid):
            field_path = _emit_is_valid_path(table_key.field)
            lookup_key[field_path] = _eval_expression(state, table_key.field, {})
            match_kinds[field_path] = table_key.match_kind
            field_widths[field_path] = 1  # isValid() returns a 1-bit value
        else:
            field_path = ".".join(table_key.field.path)
            lookup_key[field_path] = _eval_expression(state, table_key.field, {})
            match_kinds[field_path] = table_key.match_kind
            field_widths[field_path] = _resolve_field_width(state, table_key.field)

    best_match = None
    best_score = -1
    for entry in entries:
        if _entry_matches(entry, lookup_key, match_kinds, field_widths):
            priority = entry.get("priority", 0)
            prefix_total = sum(
                entry.get("prefix_len", {}).get(k, 0) for k in lookup_key
            )
            score = priority + prefix_total
            if score > best_score:
                best_match = entry
                best_score = score

    if best_match is not None:
        action_name = best_match["action"]
        _exec_action_by_name(state, action_name, best_match.get("args", {}), ctx)
        return action_name

    for const_entry in table.const_entries:
        if _const_entry_matches(state, const_entry, lookup_key):
            action_args = _build_const_entry_args(
                const_entry, ctx.actions.get(const_entry.action_name)
            )
            _exec_action_by_name(state, const_entry.action_name, action_args, ctx)
            return const_entry.action_name

    if table.default_action:
        _exec_action_by_name(state, table.default_action, {}, ctx)
    return table.default_action


def _const_entry_matches(
    state: _SimState,
    entry: ir.ConstEntry,
    lookup_key: dict[str, int],
) -> bool:
    """Check if a const entry matches the lookup key values."""
    lookup_values = tuple(lookup_key.values())
    for entry_expr, lookup_val in zip(entry.values, lookup_values, strict=True):
        if isinstance(entry_expr, ir.Wildcard):
            continue
        if isinstance(entry_expr, ir.Masked):
            entry_val = _eval_expression(state, entry_expr.value, {})
            mask_val = _eval_expression(state, entry_expr.mask, {})
            if (lookup_val & mask_val) != (entry_val & mask_val):
                return False
        else:
            entry_val = _eval_expression(state, entry_expr, {})
            if entry_val != lookup_val:
                return False
    return True


def _build_const_entry_args(
    entry: ir.ConstEntry,
    action_decl: ir.ActionDecl | None,
) -> dict[str, int]:
    """Build action args dict from a const entry's positional args."""
    if action_decl is None or not entry.action_args:
        return {}
    args = {}
    for param, arg_expr in zip(action_decl.params, entry.action_args, strict=False):
        if isinstance(arg_expr, ir.BoolLiteral):
            args[param.name] = int(arg_expr.value)
        elif isinstance(arg_expr, ir.IntLiteral):
            args[param.name] = arg_expr.value
        else:
            raise ValueError(f"Unsupported const entry arg: {arg_expr}")
    return args


def _resolve_struct_field_width(
    s: ir.StructType,
    remaining: list[str],
    struct_types: dict[str, ir.StructType],
) -> int | None:
    """Walk a struct chain to resolve a field's bit width."""
    for member in s.members:
        if member.name == remaining[0]:
            if len(remaining) == 1 and isinstance(member.type, ir.BitType):
                return member.type.width
            if len(remaining) > 1 and isinstance(member.type, str):
                inner = struct_types.get(member.type)
                if inner is not None:
                    return _resolve_struct_field_width(
                        inner, remaining[1:], struct_types
                    )
    return None


def _resolve_field_width(state: _SimState, field: ir.FieldAccess) -> int:
    """Look up the bit width of a header or metadata field."""
    path = field.path
    # Single-element path: control-local variable
    if len(path) == 1 and path[0] in state.control_local_widths:
        return state.control_local_widths[path[0]]
    # 3-element path: *.header.field
    if len(path) == 3 and path[1] in state.headers:
        header_inst = state.headers[path[1]]
        for hf in header_inst.type_info.fields:
            if hf.name == path[2]:
                return hf.type.width
    # param.field or param.struct.field -> try struct resolution then metadata_widths
    if len(path) >= 2:
        struct_types = {s.name: s for s in state.program.structs}
        remaining = list(path[1:])
        for s in state.program.structs:
            result = _resolve_struct_field_width(s, remaining, struct_types)
            if result is not None:
                return result
        # Direct metadata_widths lookup
        key = ".".join(path[1:])
        if key in state.metadata_widths:
            return state.metadata_widths[key]
        if len(path) == 2 and path[1] in state.metadata_widths:
            return state.metadata_widths[path[1]]
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
        elif kind == "ternary":
            mask = entry.get("mask", {}).get(field_path, 0)
            if (value & mask) != (entry_value & mask):
                return False
        elif kind == "optional":
            if entry_value != value:
                return False
    return True


def _exec_action_by_name(
    state: _SimState,
    action_name: str,
    args: dict[str, int],
    ctx: _ControlContext,
) -> None:
    """Execute a named action with given arguments."""
    if action_name in ("NoAction", "NoAction_0", "NoAction_1"):
        return
    action = ctx.actions[action_name]
    local_bindings: dict[str, int] = {}
    for param in action.params:
        local_bindings[param.name] = args[param.name]
    for stmt in action.body:
        _exec_statement(state, stmt, local_bindings, ctx.externs)


def _exec_statement(
    state: _SimState,
    stmt: ir.Statement,
    locals_: dict[str, int],
    externs: dict[str, object],
) -> None:
    """Execute a single statement."""
    if isinstance(stmt, ir.MethodCall):
        if stmt.method == "extract":
            _exec_extract(state, stmt.args[0])
        elif stmt.method == "count":
            pass  # Direct counter: no-op in simulation
        elif stmt.method == "read":
            # Direct meter: set the target field to GREEN (0)
            if stmt.args:
                _set_field(state, stmt.args[0], 0)
        elif stmt.method == "apply":
            pass  # Control apply: no-op in simulation (handled at pipeline level)
        else:
            raise ValueError(f"Unknown method: {stmt.method}")
    elif isinstance(stmt, ir.FunctionCall):
        if stmt.name in externs:
            externs[stmt.name](stmt)
        else:
            raise ValueError(f"Unknown function: {stmt.name}")
    elif isinstance(stmt, ir.Assignment):
        value = _eval_expression(state, stmt.value, locals_)
        _set_field(state, stmt.target, value)
    else:
        raise ValueError(f"Unsupported statement in action: {stmt}")


def _exec_extract(state: _SimState, header_ref: ir.Expression) -> None:
    """Extract a header from the packet byte buffer."""
    if not isinstance(header_ref, ir.FieldAccess):
        raise ValueError(f"Expected FieldAccess, got {header_ref}")
    header_name = header_ref.path[-1]
    hdr = state.headers[header_name]

    total_bits = sum(f.type.width for f in hdr.type_info.fields)
    available_bits = (len(state.packet_bytes) * 8) - state.cursor
    if available_bits < total_bits:
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


def compute_csum16(field_values: list[tuple[int, int]]) -> int:
    """Compute 16-bit ones' complement checksum (RFC 1071).

    Args:
        field_values: List of (value, width_in_bits) pairs.
    """
    total_bits = 0
    combined = 0
    for value, width in field_values:
        combined = (combined << width) | (value & ((1 << width) - 1))
        total_bits += width

    if total_bits % 16:
        pad = 16 - (total_bits % 16)
        combined <<= pad
        total_bits += pad

    total = 0
    num_words = total_bits // 16
    for i in range(num_words):
        shift = (num_words - 1 - i) * 16
        word = (combined >> shift) & 0xFFFF
        total += word

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def _eval_expression(
    state: _SimState, expr: ir.Expression, locals_: dict[str, int]
) -> int:
    """Evaluate an expression to an integer value."""
    if isinstance(expr, ir.BoolLiteral):
        return int(expr.value)
    if isinstance(expr, ir.IntLiteral):
        return expr.value
    if isinstance(expr, ir.FieldAccess):
        return _get_field(state, expr, locals_)
    if isinstance(expr, ir.ArithOp):
        left = _eval_expression(state, expr.left, locals_)
        right = _eval_expression(state, expr.right, locals_)
        if expr.op == "+":
            return left + right
        if expr.op == "-":
            return left - right
        raise ValueError(f"Unknown op: {expr.op}")
    if isinstance(expr, ir.IsValid):
        return int(_eval_is_valid(state, expr))
    if isinstance(expr, ir.Cast):
        inner_val = _eval_expression(state, expr.expr, locals_)
        for decl in state.program.declarations:
            if (
                isinstance(decl, (ir.TypedefDecl, ir.NewtypeDecl))
                and decl.name == expr.type_name
            ):
                return inner_val & ((1 << decl.type.width) - 1)
            if isinstance(decl, ir.EnumDecl) and decl.name == expr.type_name:
                return inner_val & ((1 << decl.underlying_type.width) - 1)
        return inner_val
    if isinstance(expr, ir.ConstRef):
        for decl in state.program.declarations:
            if isinstance(decl, ir.ConstDecl) and decl.name == expr.name:
                return decl.value
        raise ValueError(f"Unknown constant: {expr.name}")
    raise ValueError(f"Cannot evaluate: {expr}")


def _emit_is_valid_path(iv: ir.IsValid) -> str:
    """Generate a unique key for an isValid() table key."""
    return ".".join(iv.header_ref.path) + ".isValid()"


def _eval_is_valid(state: _SimState, iv: ir.IsValid) -> bool:
    """Check if a header is valid."""
    header_name = iv.header_ref.path[-1]
    return state.headers[header_name].valid


def _get_field(state: _SimState, fa: ir.FieldAccess, locals_: dict[str, int]) -> int:
    """Read a field value."""
    path = fa.path
    if len(path) == 1:
        if path[0] in locals_:
            return locals_[path[0]]
        if path[0] in state.control_locals:
            return state.control_locals[path[0]]
        raise ValueError(f"Unknown local variable: {path[0]}")
    # 3-element path: struct.header.field
    if len(path) == 3 and path[1] in state.headers:
        return state.headers[path[1]].fields.get(path[2], 0)
    # param.field or param.struct.field -> metadata lookup
    key = ".".join(path[1:])
    if key in state.metadata:
        return state.metadata[key]
    if len(path) == 2 and path[1] in state.metadata:
        return state.metadata[path[1]]
    raise ValueError(f"Cannot read field: {'.'.join(path)}")


def _set_field(state: _SimState, fa: ir.FieldAccess, value: int) -> None:
    """Write a field value."""
    path = fa.path
    if len(path) == 1:
        state.control_locals[path[0]] = value
        return
    if len(path) == 3 and path[1] in state.headers:
        state.headers[path[1]].fields[path[2]] = value
        return
    # param.field or param.struct.field -> metadata lookup
    key = ".".join(path[1:])
    if key in state.metadata:
        state.metadata[key] = value
    elif len(path) == 2 and path[1] in state.metadata:
        state.metadata[path[1]] = value
    else:
        raise ValueError(f"Cannot write field: {'.'.join(path)}")


def _run_deparser(state: _SimState, deparser: ir.DeparserDecl) -> bytearray:
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

    payload_start = state.cursor // 8
    output.extend(state.packet_bytes[payload_start:])
    return output

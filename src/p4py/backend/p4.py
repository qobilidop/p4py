"""P4-16 code emitter.

Traverses IR nodes and emits syntactically valid P4-16 source targeting v1model.
Generates boilerplate for unused v1model pipeline stages.
"""

from __future__ import annotations

from dataclasses import dataclass

from p4py.ir import nodes


def emit(program: nodes.Program | nodes.EbpfProgram) -> str:
    """Emit a P4-16 source string from an IR Program."""
    if isinstance(program, nodes.EbpfProgram):
        return _emit_ebpf(program)
    return _emit_v1model(program)


def _emit_v1model(program: nodes.Program) -> str:
    """Emit P4-16 source targeting v1model."""
    # Derive the headers and metadata struct names from the program.
    # Convention: the first struct with header-typed members is headers,
    # the last struct is metadata.
    headers_name = program.structs[0].name
    metadata_name = program.structs[-1].name
    names = _StructNames(headers=headers_name, metadata=metadata_name)

    lines: list[str] = []
    lines.append("#include <core.p4>")
    lines.append("#include <v1model.p4>")
    lines.append("")

    for h in program.headers:
        _emit_header(lines, h)
    for s in program.structs:
        _emit_struct(lines, s)

    _emit_parser(lines, program.parser, names)
    _emit_verify_checksum(lines, program.verify_checksum, names)
    _emit_control(lines, program.ingress, names)
    _emit_egress(lines, program.egress, names)
    _emit_compute_checksum(lines, program.compute_checksum, names)
    _emit_deparser(lines, program.deparser, names)
    _emit_main(lines, program)

    return "\n".join(lines) + "\n"


def _emit_ebpf(program: nodes.EbpfProgram) -> str:
    """Emit P4-16 source targeting ebpf_model."""
    headers_name = program.structs[0].name

    lines: list[str] = []
    lines.append("#include <core.p4>")
    lines.append("#include <ebpf_model.p4>")
    lines.append("")

    for h in program.headers:
        _emit_header(lines, h)
    for s in program.structs:
        _emit_struct(lines, s)

    _emit_ebpf_parser(lines, program.parser, headers_name)
    _emit_ebpf_control(lines, program.filter, headers_name)
    _emit_ebpf_main(lines, program)

    return "\n".join(lines) + "\n"


def _emit_ebpf_parser(
    lines: list[str], p: nodes.ParserDecl, headers_name: str
) -> None:
    lines.append(f"parser {p.name}(packet_in p, out {headers_name} headers) {{")
    for state in p.states:
        _emit_parser_state(lines, state)
    lines.append("}")
    lines.append("")


def _emit_ebpf_control(
    lines: list[str], c: nodes.ControlDecl, headers_name: str
) -> None:
    lines.append(
        f"control {c.name}(inout {headers_name} headers, out bool accept) {{"
    )

    for action in c.actions:
        _emit_action(lines, action)
    for table in c.tables:
        _emit_table(lines, table)

    lines.append("    apply {")
    for stmt in c.apply_body:
        _emit_block_statement(lines, stmt, indent=8)
    lines.append("    }")
    lines.append("}")
    lines.append("")


def _emit_ebpf_main(lines: list[str], program: nodes.EbpfProgram) -> None:
    lines.append(
        f"ebpfFilter({program.parser.name}(), {program.filter.name}()) main;"
    )


@dataclass
class _StructNames:
    headers: str
    metadata: str


def _emit_header(lines: list[str], h: nodes.HeaderType) -> None:
    lines.append(f"header {h.name} {{")
    for field in h.fields:
        lines.append(f"    bit<{field.type.width}> {field.name};")
    lines.append("}")
    lines.append("")


def _emit_struct(lines: list[str], s: nodes.StructType) -> None:
    lines.append(f"struct {s.name} {{")
    for member in s.members:
        if isinstance(member.type, nodes.BitType):
            lines.append(f"    bit<{member.type.width}> {member.name};")
        else:
            lines.append(f"    {member.type} {member.name};")
    lines.append("}")
    lines.append("")


def _emit_parser(lines: list[str], p: nodes.ParserDecl, names: _StructNames) -> None:
    lines.append(f"parser {p.name}(packet_in pkt,")
    lines.append(f"                out {names.headers} hdr,")
    lines.append(f"                inout {names.metadata} meta,")
    lines.append("                inout standard_metadata_t std_meta) {")
    for state in p.states:
        _emit_parser_state(lines, state)
    lines.append("}")
    lines.append("")


def _emit_parser_state(lines: list[str], state: nodes.ParserState) -> None:
    lines.append(f"    state {state.name} {{")
    for stmt in state.body:
        lines.append(f"        {_emit_statement(stmt)}")
    if isinstance(state.transition, nodes.Transition):
        lines.append(f"        transition {state.transition.next_state};")
    elif isinstance(state.transition, nodes.TransitionSelect):
        ts = state.transition
        lines.append(f"        transition select({_emit_field_access(ts.field)}) {{")
        for case in ts.cases:
            if case.value is None:
                lines.append(f"            default: {case.next_state};")
            else:
                lines.append(
                    f"            {_emit_int_literal(case.value)}: {case.next_state};"
                )
        lines.append("        }")
    lines.append("    }")


def _emit_control(lines: list[str], c: nodes.ControlDecl, names: _StructNames) -> None:
    lines.append(f"control {c.name}(inout {names.headers} hdr,")
    lines.append(f"                  inout {names.metadata} meta,")
    lines.append("                  inout standard_metadata_t std_meta) {")

    for action in c.actions:
        _emit_action(lines, action)
    for table in c.tables:
        _emit_table(lines, table)

    lines.append("    apply {")
    for stmt in c.apply_body:
        _emit_block_statement(lines, stmt, indent=8)
    lines.append("    }")
    lines.append("}")
    lines.append("")


def _emit_action(lines: list[str], a: nodes.ActionDecl) -> None:
    param_strs = []
    for p in a.params:
        if isinstance(p.type, nodes.BoolType):
            param_strs.append(f"bool {p.name}")
        else:
            param_strs.append(f"bit<{p.type.width}> {p.name}")
    params = ", ".join(param_strs)
    lines.append(f"    action {a.name}({params}) {{")
    for stmt in a.body:
        lines.append(f"        {_emit_statement(stmt)}")
    lines.append("    }")
    lines.append("")


def _emit_table(lines: list[str], t: nodes.TableDecl) -> None:
    lines.append(f"    table {t.name} {{")
    lines.append("        key = {")
    for key in t.keys:
        lines.append(
            f"            {_emit_field_access(key.field)}: {key.match_kind};"
        )
    lines.append("        }")
    lines.append("        actions = {")
    for action_name in t.actions:
        lines.append(f"            {action_name};")
    lines.append("        }")
    if t.const_entries:
        lines.append("        const entries = {")
        for entry in t.const_entries:
            values = ", ".join(_emit_expression(v) for v in entry.values)
            args = ", ".join(_emit_expression(a) for a in entry.action_args)
            lines.append(f"            ({values}) : {entry.action_name}({args});")
        lines.append("        }")
    if t.implementation:
        lines.append(f"        implementation = {t.implementation};")
    if t.default_action:
        if t.default_action_args:
            args = ", ".join(_emit_expression(a) for a in t.default_action_args)
            lines.append(f"        default_action = {t.default_action}({args});")
        else:
            lines.append(f"        default_action = {t.default_action}();")
    if t.size is not None:
        lines.append(f"        size = {t.size};")
    lines.append("    }")
    lines.append("")


def _emit_deparser(
    lines: list[str], d: nodes.DeparserDecl, names: _StructNames
) -> None:
    lines.append(f"control {d.name}(packet_out pkt, in {names.headers} hdr) {{")
    lines.append("    apply {")
    for field in d.emit_order:
        lines.append(f"        pkt.emit({_emit_field_access(field)});")
    lines.append("    }")
    lines.append("}")
    lines.append("")


def _emit_verify_checksum(
    lines: list[str], vc: nodes.ControlDecl | None, names: _StructNames
) -> None:
    if vc is not None:
        _emit_checksum_control(lines, vc, names)
    else:
        lines.append(
            f"control MyVerifyChecksum(inout {names.headers} hdr,"
            f" inout {names.metadata} meta) {{"
        )
        lines.append("    apply {}")
        lines.append("}")
        lines.append("")


def _emit_egress(
    lines: list[str], egress: nodes.ControlDecl | None, names: _StructNames
) -> None:
    if egress is not None:
        _emit_control(lines, egress, names)
    else:
        lines.append(f"control MyEgress(inout {names.headers} hdr,")
        lines.append(f"                  inout {names.metadata} meta,")
        lines.append("                  inout standard_metadata_t std_meta) {")
        lines.append("    apply {}")
        lines.append("}")
        lines.append("")


def _emit_compute_checksum(
    lines: list[str], cc: nodes.ControlDecl | None, names: _StructNames
) -> None:
    if cc is not None:
        _emit_checksum_control(lines, cc, names)
    else:
        lines.append(
            f"control MyComputeChecksum(inout {names.headers} hdr,"
            f" inout {names.metadata} meta) {{"
        )
        lines.append("    apply {}")
        lines.append("}")
        lines.append("")


def _emit_checksum_control(
    lines: list[str], c: nodes.ControlDecl, names: _StructNames
) -> None:
    lines.append(
        f"control {c.name}(inout {names.headers} hdr, inout {names.metadata} meta) {{"
    )
    lines.append("    apply {")
    for stmt in c.apply_body:
        _emit_checksum_statement(lines, stmt)
    lines.append("    }")
    lines.append("}")
    lines.append("")


def _emit_checksum_statement(lines: list[str], stmt: nodes.Statement) -> None:
    if isinstance(stmt, nodes.ChecksumVerify):
        _emit_checksum_call(lines, "verify_checksum", stmt)
    elif isinstance(stmt, nodes.ChecksumUpdate):
        _emit_checksum_call(lines, "update_checksum", stmt)
    else:
        lines.append(f"        {_emit_statement(stmt)}")


def _emit_checksum_call(
    lines: list[str],
    func_name: str,
    stmt: nodes.ChecksumVerify | nodes.ChecksumUpdate,
) -> None:
    cond = _emit_expression(stmt.condition)
    data_fields = ", ".join(_emit_field_access(f) for f in stmt.data)
    checksum = _emit_field_access(stmt.checksum)
    lines.append(f"        {func_name}(")
    lines.append(f"            {cond},")
    lines.append(f"            {{ {data_fields} }},")
    lines.append(f"            {checksum},")
    lines.append(f"            HashAlgorithm.{stmt.algo});")


def _emit_main(lines: list[str], program: nodes.Program) -> None:
    egress_name = program.egress.name if program.egress else "MyEgress"
    vc_name = (
        program.verify_checksum.name if program.verify_checksum else "MyVerifyChecksum"
    )
    cc_name = (
        program.compute_checksum.name
        if program.compute_checksum
        else "MyComputeChecksum"
    )
    lines.append("V1Switch(")
    lines.append(f"    {program.parser.name}(),")
    lines.append(f"    {vc_name}(),")
    lines.append(f"    {program.ingress.name}(),")
    lines.append(f"    {egress_name}(),")
    lines.append(f"    {cc_name}(),")
    lines.append(f"    {program.deparser.name}()")
    lines.append(") main;")


def _emit_block_statement(lines: list[str], stmt: nodes.Statement, indent: int) -> None:
    """Emit a statement that may contain nested blocks (if/else)."""
    pad = " " * indent
    if isinstance(stmt, nodes.IfElse):
        cond = _emit_expression(stmt.condition)
        lines.append(f"{pad}if ({cond}) {{")
        for s in stmt.then_body:
            _emit_block_statement(lines, s, indent + 4)
        if stmt.else_body:
            lines.append(f"{pad}}} else {{")
            for s in stmt.else_body:
                _emit_block_statement(lines, s, indent + 4)
        lines.append(f"{pad}}}")
    elif isinstance(stmt, nodes.SwitchAction):
        lines.append(f"{pad}switch ({stmt.table_name}.apply().action_run) {{")
        for case in stmt.cases:
            lines.append(f"{pad}    {case.action_name}: {{")
            for s in case.body:
                _emit_block_statement(lines, s, indent + 8)
            lines.append(f"{pad}    }}")
        lines.append(f"{pad}}}")
    else:
        lines.append(f"{pad}{_emit_statement(stmt)}")


def _emit_statement(stmt: nodes.Statement) -> str:
    """Emit a single-line statement."""
    if isinstance(stmt, nodes.Assignment):
        return f"{_emit_field_access(stmt.target)} = {_emit_expression(stmt.value)};"
    if isinstance(stmt, nodes.MethodCall):
        args = ", ".join(_emit_expression(a) for a in stmt.args)
        return f"{_emit_field_access(stmt.object)}.{stmt.method}({args});"
    if isinstance(stmt, nodes.FunctionCall):
        args = ", ".join(_emit_expression(a) for a in stmt.args)
        return f"{stmt.name}({args});"
    if isinstance(stmt, nodes.ActionCall):
        args = ", ".join(_emit_expression(a) for a in stmt.args)
        return f"{stmt.name}({args});"
    if isinstance(stmt, nodes.TableApply):
        return f"{stmt.table_name}.apply();"
    raise ValueError(f"Cannot emit statement: {stmt}")


def _emit_expression(expr: nodes.Expression) -> str:
    """Emit an expression."""
    if isinstance(expr, nodes.FieldAccess):
        return _emit_field_access(expr)
    if isinstance(expr, nodes.BoolLiteral):
        return "true" if expr.value else "false"
    if isinstance(expr, nodes.IntLiteral):
        if expr.width is not None:
            return f"{expr.width}w{expr.value}"
        return str(expr.value)
    if isinstance(expr, nodes.ArithOp):
        return f"{_emit_expression(expr.left)} {expr.op} {_emit_expression(expr.right)}"
    if isinstance(expr, nodes.IsValid):
        return f"{_emit_field_access(expr.header_ref)}.isValid()"
    raise ValueError(f"Cannot emit expression: {expr}")


def _emit_field_access(fa: nodes.FieldAccess) -> str:
    """Emit a dotted field path."""
    return ".".join(fa.path)


def _emit_int_literal(value: int) -> str:
    """Emit an integer literal, using hex for large values."""
    if value > 255:
        digits = f"{value:x}"
        # Pad to even number of nibbles (e.g. 0x800 → 0x0800).
        if len(digits) % 2:
            digits = "0" + digits
        return "0x" + digits
    return str(value)

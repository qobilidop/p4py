"""P4-16 code emitter.

Traverses IR nodes and emits syntactically valid P4-16 source targeting v1model.
Generates boilerplate for unused v1model pipeline stages.
"""

from __future__ import annotations

from p4py.ir import nodes


def emit(program: nodes.Program) -> str:
    """Emit a P4-16 source string from an IR Program."""
    lines: list[str] = []
    lines.append("#include <core.p4>")
    lines.append("#include <v1model.p4>")
    lines.append("")

    for h in program.headers:
        _emit_header(lines, h)
    for s in program.structs:
        _emit_struct(lines, s)

    _emit_parser(lines, program.parser)
    _emit_verify_checksum(lines)
    _emit_control(lines, program.ingress)
    _emit_egress(lines, program.egress)
    _emit_compute_checksum(lines)
    _emit_deparser(lines, program.deparser)
    _emit_main(lines, program)

    return "\n".join(lines) + "\n"


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


def _emit_parser(lines: list[str], p: nodes.ParserDecl) -> None:
    lines.append(f"parser {p.name}(packet_in pkt,")
    lines.append("                out headers_t hdr,")
    lines.append("                inout metadata_t meta,")
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


def _emit_control(lines: list[str], c: nodes.ControlDecl) -> None:
    lines.append(f"control {c.name}(inout headers_t hdr,")
    lines.append("                  inout metadata_t meta,")
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
    params = ", ".join(f"bit<{p.type.width}> {p.name}" for p in a.params)
    lines.append(f"    action {a.name}({params}) {{")
    for stmt in a.body:
        lines.append(f"        {_emit_statement(stmt)}")
    lines.append("    }")
    lines.append("")


def _emit_table(lines: list[str], t: nodes.TableDecl) -> None:
    lines.append(f"    table {t.name} {{")
    lines.append("        key = {")
    for key in t.keys:
        lines.append(f"            {_emit_field_access(key.field)}: {key.match_kind};")
    lines.append("        }")
    lines.append("        actions = {")
    for action_name in t.actions:
        lines.append(f"            {action_name};")
    lines.append("        }")
    if t.default_action_args:
        args = ", ".join(_emit_expression(a) for a in t.default_action_args)
        lines.append(f"        default_action = {t.default_action}({args});")
    else:
        lines.append(f"        default_action = {t.default_action}();")
    lines.append("    }")
    lines.append("")


def _emit_deparser(lines: list[str], d: nodes.DeparserDecl) -> None:
    lines.append(f"control {d.name}(packet_out pkt, in headers_t hdr) {{")
    lines.append("    apply {")
    for field in d.emit_order:
        lines.append(f"        pkt.emit({_emit_field_access(field)});")
    lines.append("    }")
    lines.append("}")
    lines.append("")


def _emit_verify_checksum(lines: list[str]) -> None:
    lines.append(
        "control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {"
    )
    lines.append("    apply {}")
    lines.append("}")
    lines.append("")


def _emit_egress(lines: list[str], egress: nodes.ControlDecl | None) -> None:
    if egress is not None:
        _emit_control(lines, egress)
    else:
        lines.append("control MyEgress(inout headers_t hdr,")
        lines.append("                  inout metadata_t meta,")
        lines.append("                  inout standard_metadata_t std_meta) {")
        lines.append("    apply {}")
        lines.append("}")
        lines.append("")


def _emit_compute_checksum(lines: list[str]) -> None:
    lines.append(
        "control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {"
    )
    lines.append("    apply {}")
    lines.append("}")
    lines.append("")


def _emit_main(lines: list[str], program: nodes.Program) -> None:
    egress_name = program.egress.name if program.egress else "MyEgress"
    lines.append("V1Switch(")
    lines.append(f"    {program.parser.name}(),")
    lines.append("    MyVerifyChecksum(),")
    lines.append(f"    {program.ingress.name}(),")
    lines.append(f"    {egress_name}(),")
    lines.append("    MyComputeChecksum(),")
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
    if isinstance(expr, nodes.IntLiteral):
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

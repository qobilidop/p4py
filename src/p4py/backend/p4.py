"""P4-16 code emitter.

Traverses IR nodes and emits syntactically valid P4-16 source.
Architecture-specific details (signatures, boilerplate, main instantiation)
are delegated to the architecture descriptor on the Package.
"""

from __future__ import annotations

from p4py.ir import nodes


def emit(package: nodes.Package) -> str:
    """Emit a P4-16 source string from a Package."""
    arch = package.arch
    lines: list[str] = []
    lines.append("#include <core.p4>")
    lines.append(f"#include <{arch.include}>")
    lines.append("")

    for h in package.headers:
        _emit_header(lines, h)
    for s in package.structs:
        _emit_struct(lines, s)

    struct_names = _derive_struct_names(package)

    for entry in package.blocks:
        sig = arch.block_signature(entry.name, struct_names)
        if entry.kind == "parser":
            _emit_parser_block(lines, entry.decl, sig)
        elif entry.kind == "deparser":
            _emit_deparser_block(lines, entry.decl, sig)
        elif entry.kind == "control":
            _emit_control_block(lines, entry.decl, sig)

    # Boilerplate for missing optional blocks.
    for spec in arch.pipeline:
        if not any(b.name == spec.name for b in package.blocks):
            arch.emit_boilerplate(lines, spec, struct_names)

    block_names = {}
    for spec in arch.pipeline:
        match = next((b for b in package.blocks if b.name == spec.name), None)
        if match:
            block_names[spec.name] = match.decl.name
        else:
            block_names[spec.name] = _boilerplate_name(spec.name)
    lines.append(arch.main_instantiation(block_names))

    return "\n".join(lines) + "\n"


def _derive_struct_names(package: nodes.Package) -> dict[str, str]:
    """Derive struct name mapping from the package."""
    names: dict[str, str] = {"headers": package.structs[0].name}
    if len(package.structs) > 1:
        names["metadata"] = package.structs[-1].name
    return names


def _boilerplate_name(block_name: str) -> str:
    """Generate a default name for a missing optional block."""
    parts = block_name.split("_")
    return "My" + "".join(p.capitalize() for p in parts)


# --- Generic block emitters ---


def _emit_parser_block(
    lines: list[str], p: nodes.ParserDecl, sig: str
) -> None:
    sig_line = sig.replace("{name}", p.name)
    lines.append(sig_line + " {")
    for state in p.states:
        _emit_parser_state(lines, state)
    lines.append("}")
    lines.append("")


def _emit_control_block(
    lines: list[str], c: nodes.ControlDecl, sig: str
) -> None:
    sig_line = sig.replace("{name}", c.name)
    lines.append(sig_line + " {")
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


def _emit_deparser_block(
    lines: list[str], d: nodes.DeparserDecl, sig: str
) -> None:
    sig_line = sig.replace("{name}", d.name)
    lines.append(sig_line + " {")
    lines.append("    apply {")
    for field in d.emit_order:
        lines.append(f"        pkt.emit({_emit_field_access(field)});")
    lines.append("    }")
    lines.append("}")
    lines.append("")


# --- Shared emitters ---


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
        if expr.hex:
            return _emit_hex_literal(expr.value)
        return str(expr.value)
    if isinstance(expr, nodes.ArithOp):
        return f"{_emit_expression(expr.left)} {expr.op} {_emit_expression(expr.right)}"
    if isinstance(expr, nodes.IsValid):
        return f"{_emit_field_access(expr.header_ref)}.isValid()"
    if isinstance(expr, nodes.ListExpression):
        inner = ", ".join(_emit_expression(e) for e in expr.elements)
        return "{ " + inner + " }"
    raise ValueError(f"Cannot emit expression: {expr}")


def _emit_field_access(fa: nodes.FieldAccess) -> str:
    """Emit a dotted field path."""
    return ".".join(fa.path)


def _emit_hex_literal(value: int) -> str:
    """Emit an integer as a hex literal, padded to even nibbles."""
    digits = f"{value:x}"
    if len(digits) % 2:
        digits = "0" + digits
    return "0x" + digits


def _emit_int_literal(value: int) -> str:
    """Emit an integer literal, using hex for large values."""
    if value > 255:
        digits = f"{value:x}"
        # Pad to even number of nibbles (e.g. 0x800 → 0x0800).
        if len(digits) % 2:
            digits = "0" + digits
        return "0x" + digits
    return str(value)

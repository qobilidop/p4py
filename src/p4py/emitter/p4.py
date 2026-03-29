"""P4-16 code emitter.

Traverses IR nodes and emits syntactically valid P4-16 source.
Architecture-specific details (signatures, boilerplate, main instantiation)
are delegated to the architecture descriptor on the Package.
"""

from __future__ import annotations

from p4py import ir


def emit(package: ir.Package) -> str:
    """Emit a P4-16 source string from a Package."""
    arch = package.arch
    lines: list[str] = []
    lines.append("#include <core.p4>")
    lines.append(f"#include <{arch.include}>")
    lines.append("")

    for decl in package.declarations:
        if isinstance(decl, ir.TypedefDecl):
            _emit_typedef(lines, decl)
        elif isinstance(decl, ir.NewtypeDecl):
            _emit_newtype(lines, decl)
        elif isinstance(decl, ir.EnumDecl):
            _emit_enum(lines, decl)
        elif isinstance(decl, ir.ConstDecl):
            _emit_const(lines, decl)
    if package.declarations:
        lines.append("")

    for h in package.headers:
        _emit_header(lines, h)
    for s in package.structs:
        _emit_struct(lines, s)

    for sc in package.sub_controls:
        _emit_sub_control(lines, sc)

    struct_names = _derive_struct_names(package)

    for spec in arch.pipeline:
        entry = next((b for b in package.blocks if b.name == spec.name), None)
        if entry is not None:
            sig = arch.block_signature(entry.name, struct_names, entry.decl.param_names)
            if entry.kind == "parser":
                _emit_parser_block(lines, entry.decl, sig)
            elif entry.kind == "deparser":
                _emit_deparser_block(lines, entry.decl, sig)
            elif entry.kind == "control":
                _emit_control_block(lines, entry.decl, sig)
        else:
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


def _derive_struct_names(package: ir.Package) -> dict[str, str]:
    """Derive struct name mapping from the package."""
    names: dict[str, str] = {"headers": package.structs[0].name}
    if len(package.structs) > 1:
        names["metadata"] = package.structs[-1].name
    return names


def _emit_sub_control(lines: list[str], c: ir.ControlDecl) -> None:
    """Emit a sub-control with its own signature (not architecture-defined)."""
    sig_parts = []
    param_names = c.param_names
    for i, pname in enumerate(param_names):
        if i < len(c.param_types):
            direction, type_name = c.param_types[i]
            if direction:
                sig_parts.append(f"{direction} {type_name} {pname}")
            else:
                sig_parts.append(f"{type_name} {pname}")
        else:
            sig_parts.append(pname)

    prefix = f"control {c.name}("
    padding = " " * len(prefix)
    sig = prefix + (",\n" + padding).join(sig_parts) + ")"

    lines.append(sig + " {")
    for lv in c.local_vars:
        lines.append(f"    bit<{lv.type.width}> {lv.name} = {lv.init_value};")
        lines.append("")
    for dc in c.direct_counters:
        lines.append(f"    direct_counter(CounterType.{dc.counter_type}) {dc.name};")
        lines.append("")
    for dm in c.direct_meters:
        lines.append(
            f"    direct_meter<{dm.result_type_name}>"
            f"(MeterType.{dm.meter_type}) {dm.name};"
        )
        lines.append("")
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


def _boilerplate_name(block_name: str) -> str:
    """Generate a default name for a missing optional block."""
    parts = block_name.split("_")
    return "My" + "".join(p.capitalize() for p in parts)


# --- Generic block emitters ---


def _emit_parser_block(lines: list[str], p: ir.ParserDecl, sig: str) -> None:
    sig_line = sig.replace("{name}", p.name)
    lines.append(sig_line + " {")
    for state in p.states:
        _emit_parser_state(lines, state)
    lines.append("}")
    lines.append("")


def _emit_control_block(lines: list[str], c: ir.ControlDecl, sig: str) -> None:
    sig_line = sig.replace("{name}", c.name)
    lines.append(sig_line + " {")
    for lv in c.local_vars:
        lines.append(f"    bit<{lv.type.width}> {lv.name} = {lv.init_value};")
        lines.append("")
    for dc in c.direct_counters:
        lines.append(f"    direct_counter(CounterType.{dc.counter_type}) {dc.name};")
        lines.append("")
    for dm in c.direct_meters:
        lines.append(
            f"    direct_meter<{dm.result_type_name}>"
            f"(MeterType.{dm.meter_type}) {dm.name};"
        )
        lines.append("")
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


def _emit_deparser_block(lines: list[str], d: ir.DeparserDecl, sig: str) -> None:
    sig_line = sig.replace("{name}", d.name)
    pkt_name = d.param_names[0] if d.param_names else "pkt"
    lines.append(sig_line + " {")
    lines.append("    apply {")
    for field in d.emit_order:
        lines.append(f"        {pkt_name}.emit({_emit_field_access(field)});")
    lines.append("    }")
    lines.append("}")
    lines.append("")


# --- Shared emitters ---


def _emit_header(lines: list[str], h: ir.HeaderType) -> None:
    lines.append(f"header {h.name} {{")
    for field in h.fields:
        if field.type_name:
            lines.append(f"    {field.type_name} {field.name};")
        else:
            lines.append(f"    bit<{field.type.width}> {field.name};")
    lines.append("}")
    lines.append("")


def _emit_struct(lines: list[str], s: ir.StructType) -> None:
    lines.append(f"struct {s.name} {{")
    for member in s.members:
        if isinstance(member.type, ir.BitType):
            lines.append(f"    bit<{member.type.width}> {member.name};")
        elif isinstance(member.type, ir.BoolType):
            lines.append(f"    bool {member.name};")
        else:
            lines.append(f"    {member.type} {member.name};")
    lines.append("}")
    lines.append("")


def _emit_typedef(lines: list[str], td: ir.TypedefDecl) -> None:
    lines.append(f"typedef bit<{td.type.width}> {td.name};")


def _emit_newtype(lines: list[str], nt: ir.NewtypeDecl) -> None:
    lines.append(f"type bit<{nt.type.width}> {nt.name};")


def _emit_enum(lines: list[str], e: ir.EnumDecl) -> None:
    lines.append(f"enum bit<{e.underlying_type.width}> {e.name} {{")
    for i, member in enumerate(e.members):
        comma = "," if i < len(e.members) - 1 else ""
        lines.append(f"    {member.name} = {member.value}{comma}")
    lines.append("};")
    lines.append("")


def _emit_const(lines: list[str], c: ir.ConstDecl) -> None:
    if c.value > 255:
        val = _emit_hex_literal(c.value)
    else:
        val = str(c.value)
    lines.append(f"const {c.type_name} {c.name} = {val};")


def _emit_parser_state(lines: list[str], state: ir.ParserState) -> None:
    lines.append(f"    state {state.name} {{")
    for stmt in state.body:
        lines.append(f"        {_emit_statement(stmt)}")
    if isinstance(state.transition, ir.Transition):
        lines.append(f"        transition {state.transition.next_state};")
    elif isinstance(state.transition, ir.TransitionSelect):
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


def _emit_action(lines: list[str], a: ir.ActionDecl) -> None:
    param_strs = []
    for p in a.params:
        if isinstance(p.type, ir.BoolType):
            param_strs.append(f"bool {p.name}")
        else:
            param_strs.append(f"bit<{p.type.width}> {p.name}")
    params = ", ".join(param_strs)
    lines.append(f"    action {a.name}({params}) {{")
    for stmt in a.body:
        lines.append(f"        {_emit_statement(stmt)}")
    lines.append("    }")
    lines.append("")


def _emit_table(lines: list[str], t: ir.TableDecl) -> None:
    lines.append(f"    table {t.name} {{")
    lines.append("        key = {")
    for key in t.keys:
        if isinstance(key.field, ir.IsValid):
            lines.append(
                f"            {_emit_expression(key.field)}: {key.match_kind};"
            )
        else:
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
    if t.meters:
        lines.append(f"        meters = {t.meters};")
    if t.counters:
        lines.append(f"        counters = {t.counters};")
    if t.size is not None:
        lines.append(f"        size = {t.size};")
    lines.append("    }")
    lines.append("")


def _emit_block_statement(lines: list[str], stmt: ir.Statement, indent: int) -> None:
    """Emit a statement that may contain nested blocks (if/else)."""
    pad = " " * indent
    if isinstance(stmt, ir.IfElse):
        cond = _emit_expression(stmt.condition)
        lines.append(f"{pad}if ({cond}) {{")
        for s in stmt.then_body:
            _emit_block_statement(lines, s, indent + 4)
        if (
            stmt.else_body
            and len(stmt.else_body) == 1
            and isinstance(stmt.else_body[0], ir.IfElse)
        ):
            inner = stmt.else_body[0]
            inner_cond = _emit_expression(inner.condition)
            lines.append(f"{pad}}} else if ({inner_cond}) {{")
            for s in inner.then_body:
                _emit_block_statement(lines, s, indent + 4)
            if inner.else_body:
                lines.append(f"{pad}}} else {{")
                for s in inner.else_body:
                    _emit_block_statement(lines, s, indent + 4)
            lines.append(f"{pad}}}")
        elif stmt.else_body:
            lines.append(f"{pad}}} else {{")
            for s in stmt.else_body:
                _emit_block_statement(lines, s, indent + 4)
            lines.append(f"{pad}}}")
        else:
            lines.append(f"{pad}}}")
    elif isinstance(stmt, ir.SwitchAction):
        lines.append(f"{pad}switch ({stmt.table_name}.apply().action_run) {{")
        for case in stmt.cases:
            lines.append(f"{pad}    {case.action_name}: {{")
            for s in case.body:
                _emit_block_statement(lines, s, indent + 8)
            lines.append(f"{pad}    }}")
        lines.append(f"{pad}}}")
    else:
        text = _emit_statement(stmt)
        if "\n" in text:
            for line in text.split("\n"):
                lines.append(f"{pad}{line}")
        else:
            lines.append(f"{pad}{text}")


def _emit_statement(stmt: ir.Statement) -> str:
    """Emit a single-line statement."""
    if isinstance(stmt, ir.Assignment):
        return f"{_emit_field_access(stmt.target)} = {_emit_expression(stmt.value)};"
    if isinstance(stmt, ir.MethodCall):
        args = ", ".join(_emit_expression(a) for a in stmt.args)
        return f"{_emit_field_access(stmt.object)}.{stmt.method}({args});"
    if isinstance(stmt, ir.FunctionCall):
        if any(isinstance(a, ir.ListExpression) for a in stmt.args):
            return _emit_multiline_function_call(stmt)
        args = ", ".join(_emit_expression(a) for a in stmt.args)
        return f"{stmt.name}({args});"
    if isinstance(stmt, ir.ActionCall):
        args = ", ".join(_emit_expression(a) for a in stmt.args)
        return f"{stmt.name}({args});"
    if isinstance(stmt, ir.TableApply):
        return f"{stmt.table_name}.apply();"
    raise ValueError(f"Cannot emit statement: {stmt}")


def _emit_multiline_function_call(stmt: ir.FunctionCall) -> str:
    """Emit a function call with one arg per line (for checksum-style calls)."""
    parts = [f"{stmt.name}("]
    for i, arg in enumerate(stmt.args):
        suffix = "," if i < len(stmt.args) - 1 else ");"
        parts.append(f"    {_emit_expression(arg)}{suffix}")
    return "\n".join(parts)


def _emit_expression(expr: ir.Expression) -> str:
    """Emit an expression."""
    if isinstance(expr, ir.FieldAccess):
        return _emit_field_access(expr)
    if isinstance(expr, ir.BoolLiteral):
        return "true" if expr.value else "false"
    if isinstance(expr, ir.IntLiteral):
        if expr.width is not None:
            return f"{expr.width}w{expr.value}"
        if expr.hex:
            return _emit_hex_literal(expr.value)
        return str(expr.value)
    if isinstance(expr, ir.ArithOp):
        return f"{_emit_expression(expr.left)} {expr.op} {_emit_expression(expr.right)}"
    if isinstance(expr, ir.IsValid):
        return f"{_emit_field_access(expr.header_ref)}.isValid()"
    if isinstance(expr, ir.ListExpression):
        inner = ", ".join(_emit_expression(e) for e in expr.elements)
        return "{ " + inner + " }"
    if isinstance(expr, ir.Masked):
        return f"{_emit_expression(expr.value)} &&& {_emit_expression(expr.mask)}"
    if isinstance(expr, ir.Wildcard):
        return "_"
    raise ValueError(f"Cannot emit expression: {expr}")


def _emit_field_access(fa: ir.FieldAccess) -> str:
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

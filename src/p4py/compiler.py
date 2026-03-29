"""Compiles P4Py language specs into IR nodes.

Parses Python AST from captured function sources and produces IR Package.
"""

from __future__ import annotations

import ast

from p4py import ir


def compile(pipeline) -> ir.Package:
    """Compile a pipeline into a Package."""
    arch = pipeline.arch
    headers_ir = _compile_types(pipeline.headers)
    structs_ir = _compile_structs(pipeline)
    declarations_ir = _compile_declarations(getattr(pipeline, "declarations", ()))

    blocks = []
    for spec in arch.pipeline:
        block_src = getattr(pipeline, spec.name, None)
        if block_src is None:
            continue
        if spec.kind == "parser":
            decl = _compile_parser(block_src)
        elif spec.kind == "control":
            decl = _compile_control(block_src)
        elif spec.kind == "deparser":
            decl = _compile_deparser(block_src)
        else:
            raise ValueError(f"Unknown block kind: {spec.kind}")
        blocks.append(ir.BlockEntry(name=spec.name, kind=spec.kind, decl=decl))

    sub_controls_ir = _compile_sub_controls(getattr(pipeline, "sub_controls", ()))

    return ir.Package(
        arch=arch,
        headers=headers_ir,
        structs=structs_ir,
        blocks=tuple(blocks),
        declarations=declarations_ir,
        sub_controls=sub_controls_ir,
    )


def _compile_declarations(declarations) -> tuple:
    """Convert DSL declaration objects to IR declaration nodes."""
    result = []
    for decl in declarations:
        if not hasattr(decl, "_p4_kind"):
            continue
        kind = decl._p4_kind
        if kind == "typedef":
            result.append(
                ir.TypedefDecl(name=decl._p4_name, type=ir.BitType(decl.width))
            )
        elif kind == "newtype":
            result.append(
                ir.NewtypeDecl(name=decl._p4_name, type=ir.BitType(decl.width))
            )
        elif kind == "enum":
            result.append(
                ir.EnumDecl(
                    name=decl._p4_name,
                    underlying_type=ir.BitType(decl._p4_underlying.width),
                    members=tuple(ir.EnumMember(n, v) for n, v in decl._p4_members),
                )
            )
        elif kind == "const":
            result.append(
                ir.ConstDecl(
                    name=decl._p4_name,
                    type_name=decl._p4_type_name,
                    value=decl._p4_value,
                )
            )
    return tuple(result)


def _compile_sub_controls(sub_controls) -> tuple[ir.ControlDecl, ...]:
    """Compile sub-control specs into ControlDecl IR nodes."""
    result = []
    for spec in sub_controls:
        decl = _compile_control(spec)
        param_types = _extract_param_types(spec)
        # Replace the ControlDecl with one that includes param_types.
        if param_types:
            decl = ir.ControlDecl(
                name=decl.name,
                actions=decl.actions,
                tables=decl.tables,
                apply_body=decl.apply_body,
                param_names=decl.param_names,
                direct_counters=decl.direct_counters,
                direct_meters=decl.direct_meters,
                local_vars=decl.local_vars,
                param_types=param_types,
            )
        result.append(decl)
    return tuple(result)


def _extract_param_types(spec) -> tuple[tuple[str, str], ...]:
    """Extract (direction, type_name) pairs from a spec's annotations."""
    from p4py.lang import _DirectedType

    result = []
    for ann in spec._p4_annotations.values():
        if isinstance(ann, _DirectedType):
            result.append((ann.direction, ann.type_ref._p4_name))
        elif hasattr(ann, "_p4_name"):
            result.append(("", ann._p4_name))
    return tuple(result)


def _compile_types(headers_struct: type) -> tuple[ir.HeaderType, ...]:
    """Extract HeaderType IR nodes from a headers struct class."""
    result = []
    seen: set[str] = set()
    for _, header_cls in headers_struct._p4_members:
        if header_cls._p4_name in seen:
            continue
        seen.add(header_cls._p4_name)
        fields = []
        for name, bt in header_cls._p4_fields:
            if hasattr(bt, "_p4_kind") and bt._p4_kind in ("typedef", "newtype"):
                fields.append(ir.HeaderField(name, ir.BitType(bt.width), bt._p4_name))
            else:
                fields.append(ir.HeaderField(name, ir.BitType(bt.width)))
        result.append(ir.HeaderType(name=header_cls._p4_name, fields=tuple(fields)))
    return tuple(result)


def _compile_structs(pipeline) -> tuple[ir.StructType, ...]:
    """Compile struct types to IR."""
    import p4py.lang as p4
    from p4py.lang import struct as p4_struct

    result = []
    seen: set[str] = set()

    def _compile_one(s: type) -> None:
        if s._p4_name in seen:
            return
        # Compile inner structs first so they appear before outer structs.
        for _, ann in s._p4_members:
            if isinstance(ann, type) and issubclass(ann, p4_struct):
                _compile_one(ann)
        members = []
        for name, ann in s._p4_members:
            if (isinstance(ann, type) and issubclass(ann, (p4.header, p4_struct))) or (
                hasattr(ann, "_p4_kind")
                and ann._p4_kind
                in (
                    "typedef",
                    "newtype",
                    "enum",
                )
            ):
                members.append(ir.StructMember(name, ann._p4_name))
            elif isinstance(ann, p4.BoolType):
                members.append(ir.StructMember(name, ir.BoolType()))
            elif hasattr(ann, "width"):
                members.append(ir.StructMember(name, ir.BitType(ann.width)))
            else:
                members.append(ir.StructMember(name, ann._p4_name))
        result.append(ir.StructType(name=s._p4_name, members=tuple(members)))
        seen.add(s._p4_name)

    _compile_one(pipeline.headers)
    if hasattr(pipeline, "metadata") and pipeline.metadata is not None:
        _compile_one(pipeline.metadata)
    return tuple(result)


def _parse_spec_ast(spec) -> ast.FunctionDef:
    """Parse a spec's source into a FunctionDef AST node."""
    tree = ast.parse(spec._p4_source)
    # The source is a decorated function; find the FunctionDef.
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == spec._p4_name:
            return node
    raise ValueError(f"Could not find function '{spec._p4_name}' in source")


def _ast_to_field_access(node: ast.expr) -> ir.FieldAccess:
    """Convert an AST attribute chain to a FieldAccess IR node."""
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    else:
        raise ValueError(f"Unexpected AST node in field access: {ast.dump(current)}")
    return ir.FieldAccess(path=tuple(reversed(parts)))


def _ast_to_expression(node: ast.expr) -> ir.Expression:
    """Convert an AST expression to an IR Expression."""
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return ir.BoolLiteral(value=node.value)
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return ir.IntLiteral(value=node.value)
    # p4.literal(value, width=N) → IntLiteral with width
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "literal"
        and len(node.args) == 1
    ):
        value = node.args[0].value
        width = None
        for kw in node.keywords:
            if kw.arg == "width":
                width = kw.value.value
        return ir.IntLiteral(value=value, width=width)
    # p4.hex(value) → IntLiteral with hex=True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "hex"
        and len(node.args) == 1
    ):
        return ir.IntLiteral(value=node.args[0].value, hex=True)
    # p4.mask(value, mask) → Masked
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "mask"
        and len(node.args) == 2
    ):
        return ir.Masked(
            value=_ast_to_expression(node.args[0]),
            mask=_ast_to_expression(node.args[1]),
        )
    # p4.cast(type, expr) → Cast
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "cast"
        and len(node.args) == 2
    ):
        type_arg = node.args[0]
        if isinstance(type_arg, ast.Name):
            type_name = type_arg.id
        elif isinstance(type_arg, ast.Attribute):
            type_name = type_arg.attr
        else:
            raise ValueError(f"Unsupported cast type: {ast.dump(type_arg)}")
        inner_expr = _ast_to_expression(node.args[1])
        return ir.Cast(type_name=type_name, expr=inner_expr)
    if isinstance(node, ast.Constant) and node.value is None:
        return ir.Wildcard()
    if isinstance(node, (ast.Attribute, ast.Name)):
        return _ast_to_field_access(node)
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            op = "+"
        elif isinstance(node.op, ast.Sub):
            op = "-"
        else:
            raise ValueError(f"Unsupported arithmetic operator: {ast.dump(node.op)}")
        return ir.ArithOp(
            op=op,
            left=_ast_to_expression(node.left),
            right=_ast_to_expression(node.right),
        )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "isValid"
    ):
        header_ref = _ast_to_field_access(node.func.value)
        return ir.IsValid(header_ref=header_ref)
    if isinstance(node, ast.List):
        return ir.ListExpression(
            elements=tuple(_ast_to_expression(elt) for elt in node.elts)
        )
    raise ValueError(f"Unsupported expression: {ast.dump(node)}")


def _ast_to_statement(
    node: ast.stmt, params: set[str], control_locals: frozenset[str] = frozenset()
) -> ir.Statement:
    """Convert an AST statement to an IR Statement."""
    # Assignment: target = value
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        target = _ast_to_field_access(node.targets[0])
        value = _ast_to_expression(node.value)
        return ir.Assignment(target=target, value=value)

    # Expression statement (method call, function call, etc.)
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        return _ast_call_to_statement(node.value, params, control_locals)

    # If/else
    if isinstance(node, ast.If):
        condition = _ast_to_expression(node.test)
        then_body = tuple(
            s
            for n in node.body
            if (s := _ast_to_statement(n, params, control_locals)) is not None
        )
        else_body = []
        for n in node.orelse:
            if isinstance(n, ast.If):
                else_body.append(_ast_to_statement(n, params, control_locals))
            else:
                s = _ast_to_statement(n, params, control_locals)
                if s is not None:
                    else_body.append(s)
        else_body = tuple(else_body)
        return ir.IfElse(condition=condition, then_body=then_body, else_body=else_body)

    # match table.apply(): case "action": ... → SwitchAction
    if isinstance(node, ast.Match):
        subject = node.subject
        if (
            isinstance(subject, ast.Call)
            and isinstance(subject.func, ast.Attribute)
            and subject.func.attr == "apply"
        ):
            table_name = subject.func.value.id
            cases = []
            for case in node.cases:
                if isinstance(case.pattern, ast.MatchValue):
                    action_name = case.pattern.value.value
                    body = tuple(
                        s
                        for n in case.body
                        if (s := _ast_to_statement(n, params)) is not None
                    )
                    cases.append(
                        ir.SwitchActionCase(action_name=action_name, body=body)
                    )
            return ir.SwitchAction(table_name=table_name, cases=tuple(cases))

    # pass → empty body (e.g., no-op actions)
    if isinstance(node, ast.Pass):
        return None

    raise ValueError(f"Unsupported statement: {ast.dump(node)}")


def _ast_call_to_statement(
    call: ast.Call, params: set[str], control_locals: frozenset[str] = frozenset()
) -> ir.Statement:
    """Convert an AST Call to a Statement (MethodCall, FunctionCall, etc.)."""
    # obj.method(args) — e.g., pkt.extract(hdr.ethernet)
    if isinstance(call.func, ast.Attribute):
        attr = call.func
        # table.apply() (no args)
        if attr.attr == "apply" and isinstance(attr.value, ast.Name) and not call.args:
            return ir.TableApply(table_name=attr.value.id)
        # control.apply(args) — control instantiation apply
        if (
            attr.attr == "apply"
            and isinstance(attr.value, ast.Name)
            and attr.value.id not in params
            and call.args
        ):
            obj = ir.FieldAccess(path=(attr.value.id,))
            args = tuple(_ast_to_expression(a) for a in call.args)
            return ir.MethodCall(object=obj, method="apply", args=args)
        # Control-local object method call (counter.count(), meter.read())
        if isinstance(attr.value, ast.Name) and attr.value.id in control_locals:
            obj = ir.FieldAccess(path=(attr.value.id,))
            args = tuple(_ast_to_expression(a) for a in call.args)
            return ir.MethodCall(object=obj, method=attr.attr, args=args)
        # Module-qualified function: name.func(args) where name is not a
        # block parameter (e.g. v1model.mark_to_drop).  Strip the module
        # prefix and emit a plain FunctionCall.
        if isinstance(attr.value, ast.Name) and attr.value.id not in params:
            module_name = attr.value.id
            if call.keywords:
                args = []
                for kw in call.keywords:
                    expr = _ast_to_expression(kw.value)
                    if isinstance(expr, ir.FieldAccess) and expr.path[0] == module_name:
                        expr = ir.FieldAccess(path=expr.path[1:])
                    args.append(expr)
                args = tuple(args)
            else:
                args = []
                for a in call.args:
                    expr = _ast_to_expression(a)
                    # Strip module prefix from arguments
                    if (
                        isinstance(expr, ir.FieldAccess)
                        and len(expr.path) > 1
                        and expr.path[0] == module_name
                    ):
                        expr = ir.FieldAccess(path=expr.path[1:])
                    args.append(expr)
                args = tuple(args)
            return ir.FunctionCall(name=attr.attr, args=args)
        obj = _ast_to_field_access(attr.value)
        args = tuple(_ast_to_expression(a) for a in call.args)
        return ir.MethodCall(object=obj, method=attr.attr, args=args)

    # free_function(args) — e.g., mark_to_drop(std_meta), drop()
    if isinstance(call.func, ast.Name):
        args = tuple(_ast_to_expression(a) for a in call.args)
        return ir.FunctionCall(name=call.func.id, args=args)

    raise ValueError(f"Unsupported call: {ast.dump(call)}")


# --- Parser compilation ---


def _param_names(func_def: ast.FunctionDef) -> set[str]:
    """Extract parameter names from a FunctionDef."""
    return {arg.arg for arg in func_def.args.args}


def _param_names_ordered(func_def: ast.FunctionDef) -> tuple[str, ...]:
    """Extract parameter names in declaration order."""
    return tuple(arg.arg for arg in func_def.args.args)


def _compile_parser(spec) -> ir.ParserDecl:
    """Compile a @p4.parser spec into a ParserDecl."""
    func_def = _parse_spec_ast(spec)
    params = _param_names(func_def)
    states = []
    for node in func_def.body:
        if isinstance(node, ast.FunctionDef):
            states.append(_compile_parser_state(node, params))
    return ir.ParserDecl(
        name=spec._p4_name,
        states=tuple(states),
        param_names=_param_names_ordered(func_def),
    )


def _compile_parser_state(
    func_def: ast.FunctionDef, params: set[str]
) -> ir.ParserState:
    """Compile a nested function into a ParserState."""
    body_stmts: list[ir.Statement] = []
    transition: ir.Transition | ir.TransitionSelect | None = None

    for node in func_def.body:
        # return <state> — unconditional transition
        if isinstance(node, ast.Return):
            transition = _compile_transition(node)
        # match ... — transition select
        elif isinstance(node, ast.Match):
            transition = _compile_transition_select(node)
        # Other statements (extract, etc.)
        else:
            body_stmts.append(_ast_to_statement(node, params))

    if transition is None:
        raise ValueError(
            f"Parser state '{func_def.name}' has no transition (return or match)"
        )
    return ir.ParserState(
        name=func_def.name,
        body=tuple(body_stmts),
        transition=transition,
    )


def _compile_transition(ret: ast.Return) -> ir.Transition:
    """Compile a return statement to a Transition."""
    if isinstance(ret.value, ast.Name):
        return ir.Transition(next_state=ret.value.id)
    if isinstance(ret.value, ast.Attribute):
        # p4.ACCEPT, p4.REJECT
        return ir.Transition(next_state=ret.value.attr.lower())
    if isinstance(ret.value, ast.Constant) and isinstance(ret.value.value, str):
        return ir.Transition(next_state=ret.value.value)
    raise ValueError(f"Unsupported transition: {ast.dump(ret)}")


def _compile_transition_select(match: ast.Match) -> ir.TransitionSelect:
    """Compile a match statement to a TransitionSelect."""
    field = _ast_to_field_access(match.subject)
    cases = []
    for case in match.cases:
        # Extract the return value from the case body.
        if len(case.body) != 1 or not isinstance(case.body[0], ast.Return):
            raise ValueError("match cases must contain exactly one return statement")
        ret = case.body[0]

        # Default case: case _
        if isinstance(case.pattern, ast.MatchAs) and case.pattern.name is None:
            value = None
        # Value case: case 0x0800 or case Ns.CONST_NAME
        elif isinstance(case.pattern, ast.MatchValue):
            if isinstance(case.pattern.value, ast.Constant):
                value = case.pattern.value.value
            elif isinstance(case.pattern.value, ast.Name):
                value = ir.ConstRef(name=case.pattern.value.id)
            elif isinstance(case.pattern.value, ast.Attribute):
                value = ir.ConstRef(name=case.pattern.value.attr)
            else:
                raise ValueError(f"Unsupported match value: {ast.dump(case.pattern)}")
        else:
            raise ValueError(f"Unsupported match pattern: {ast.dump(case.pattern)}")

        transition = _compile_transition(ret)
        cases.append(ir.SelectCase(value=value, next_state=transition.next_state))

    return ir.TransitionSelect(field=field, cases=tuple(cases))


# --- Control compilation ---


def _compile_control(spec) -> ir.ControlDecl:
    """Compile a @p4.control spec into a ControlDecl."""
    func_def = _parse_spec_ast(spec)
    params = _param_names(func_def)

    actions: list[ir.ActionDecl] = []
    tables: list[ir.TableDecl] = []
    apply_body: list[ir.Statement] = []
    direct_counters: list[ir.DirectCounter] = []
    direct_meters: list[ir.DirectMeter] = []
    local_vars: list[ir.LocalVarDecl] = []

    # First pass: collect direct counters and meters to build control-local names.
    for node in func_def.body:
        if isinstance(node, ast.Assign) and _is_direct_counter(node):
            direct_counters.append(_compile_direct_counter(node))
        elif isinstance(node, ast.Assign) and _is_direct_meter(node):
            direct_meters.append(_compile_direct_meter(node))

    control_local_names = frozenset(
        {dc.name for dc in direct_counters} | {dm.name for dm in direct_meters}
    )

    # Second pass: compile all nodes.
    for node in func_def.body:
        # @p4.action decorated function → ActionDecl
        if isinstance(node, ast.FunctionDef) and _has_p4_decorator(node, "action"):
            actions.append(_compile_action(node, params, control_local_names))
        # name = p4.table(...) → TableDecl
        elif isinstance(node, ast.Assign) and _is_table_call(node):
            tables.append(_compile_table(node))
        # name = p4.bit(W) → LocalVarDecl
        elif isinstance(node, ast.Assign) and _is_local_var_decl(node):
            local_vars.append(_compile_local_var(node))
        # name = v1model.direct_counter(...) → DirectCounter (already collected)
        elif (
            (isinstance(node, ast.Assign) and _is_direct_counter(node))
            or (isinstance(node, ast.Assign) and _is_direct_meter(node))
            or isinstance(node, ast.Pass)
        ):
            continue
        # Everything else → apply body
        else:
            apply_body.append(_ast_to_statement(node, params))

    return ir.ControlDecl(
        name=spec._p4_name,
        actions=tuple(actions),
        tables=tuple(tables),
        apply_body=tuple(apply_body),
        param_names=_param_names_ordered(func_def),
        direct_counters=tuple(direct_counters),
        direct_meters=tuple(direct_meters),
        local_vars=tuple(local_vars),
    )


def _has_p4_decorator(node: ast.FunctionDef, name: str) -> bool:
    """Check if a function has a @p4.<name> decorator."""
    for dec in node.decorator_list:
        if isinstance(dec, ast.Attribute) and dec.attr == name:
            return True
    return False


def _compile_action(
    func_def: ast.FunctionDef,
    block_params: set[str],
    control_locals: frozenset[str] = frozenset(),
) -> ir.ActionDecl:
    """Compile a @p4.action function into an ActionDecl."""
    action_params = []
    for arg in func_def.args.args:
        if arg.annotation is not None:
            # p4.bool → BoolType
            if (
                isinstance(arg.annotation, ast.Attribute)
                and arg.annotation.attr == "bool"
            ):
                action_params.append(ir.ActionParam(name=arg.arg, type=ir.BoolType()))
            # p4.bit(W) → BitType
            elif (
                isinstance(arg.annotation, ast.Call)
                and isinstance(arg.annotation.func, ast.Attribute)
                and arg.annotation.func.attr == "bit"
            ):
                width = arg.annotation.args[0].value
                action_params.append(
                    ir.ActionParam(name=arg.arg, type=ir.BitType(width))
                )
            else:
                raise ValueError(
                    f"Action param '{arg.arg}' must be annotated"
                    " with p4.bit(W) or p4.bool"
                )

    body = tuple(
        s
        for node in func_def.body
        if (s := _ast_to_statement(node, block_params, control_locals)) is not None
    )
    return ir.ActionDecl(name=func_def.name, params=tuple(action_params), body=body)


def _is_table_call(node: ast.Assign) -> bool:
    """Check if an assignment is name = p4.table(...)."""
    if not isinstance(node.value, ast.Call):
        return False
    func = node.value.func
    return isinstance(func, ast.Attribute) and func.attr == "table"


def _is_local_var_decl(node: ast.Assign) -> bool:
    """Check if assignment is name = p4.bit(W) (local variable declaration)."""
    if not isinstance(node.value, ast.Call):
        return False
    func = node.value.func
    return isinstance(func, ast.Attribute) and func.attr == "bit"


def _compile_local_var(node: ast.Assign) -> ir.LocalVarDecl:
    """Compile name = p4.bit(W) to LocalVarDecl."""
    name = node.targets[0].id
    width = node.value.args[0].value
    return ir.LocalVarDecl(name=name, type=ir.BitType(width), init_value=0)


def _is_direct_counter(node: ast.Assign) -> bool:
    """Check if assignment is name = v1model.direct_counter(...)."""
    if not isinstance(node.value, ast.Call):
        return False
    func = node.value.func
    return isinstance(func, ast.Attribute) and func.attr == "direct_counter"


def _compile_direct_counter(node: ast.Assign) -> ir.DirectCounter:
    """Compile name = v1model.direct_counter(...) to DirectCounter."""
    name = node.targets[0].id
    counter_type = node.value.args[0].value
    return ir.DirectCounter(name=name, counter_type=counter_type)


def _is_direct_meter(node: ast.Assign) -> bool:
    """Check if assignment is name = v1model.direct_meter(...)."""
    if not isinstance(node.value, ast.Call):
        return False
    func = node.value.func
    return isinstance(func, ast.Attribute) and func.attr == "direct_meter"


def _compile_direct_meter(node: ast.Assign) -> ir.DirectMeter:
    """Compile name = v1model.direct_meter(...) to DirectMeter."""
    name = node.targets[0].id
    call = node.value
    result_type_name = (
        call.args[0].id if isinstance(call.args[0], ast.Name) else call.args[0].attr
    )
    meter_type = call.args[1].value
    return ir.DirectMeter(
        name=name, result_type_name=result_type_name, meter_type=meter_type
    )


def _compile_table(node: ast.Assign) -> ir.TableDecl:
    """Compile name = p4.table(...) into a TableDecl."""
    name = node.targets[0].id
    call = node.value

    keys = ()
    actions = ()
    default_action = ""
    default_action_args: tuple[ir.Expression, ...] = ()
    size = None
    const_entries: tuple[ir.ConstEntry, ...] = ()
    implementation: str | None = None
    counters = None
    meters = None

    for kw in call.keywords:
        if kw.arg == "key":
            keys = _compile_table_keys(kw.value)
        elif kw.arg == "actions":
            action_names = []
            for elt in kw.value.elts:
                if isinstance(elt, ast.Name):
                    action_names.append(elt.id)
                elif isinstance(elt, ast.Attribute):
                    action_names.append(elt.attr)
                else:
                    raise ValueError(f"Unsupported action ref: {ast.dump(elt)}")
            actions = tuple(action_names)
        elif kw.arg == "default_action":
            if isinstance(kw.value, ast.Name):
                default_action = kw.value.id
            elif isinstance(kw.value, ast.Attribute):
                default_action = kw.value.attr
            elif isinstance(kw.value, ast.Call):
                default_action = kw.value.func.id
                default_action_args = tuple(
                    _ast_to_expression(a) for a in kw.value.args
                )
        elif (
            kw.arg == "size"
            and isinstance(kw.value, ast.Constant)
            and isinstance(kw.value.value, int)
        ):
            size = kw.value.value
        elif kw.arg == "const_entries":
            const_entries = _compile_const_entries(kw.value)
        elif kw.arg == "counters":
            if isinstance(kw.value, ast.Name):
                counters = kw.value.id
        elif kw.arg == "meters":
            if isinstance(kw.value, ast.Name):
                meters = kw.value.id
        elif kw.arg == "implementation":
            implementation = _compile_implementation(kw.value)

    return ir.TableDecl(
        name=name,
        keys=keys,
        actions=actions,
        default_action=default_action,
        default_action_args=default_action_args,
        size=size,
        const_entries=const_entries,
        implementation=implementation,
        counters=counters,
        meters=meters,
    )


def _compile_table_keys(dict_node: ast.Dict) -> tuple[ir.TableKey, ...]:
    """Compile a dict literal {field: match_kind} into TableKeys."""
    keys = []
    for key_node, val_node in zip(dict_node.keys, dict_node.values, strict=True):
        # Handle isValid() as table key
        if (
            isinstance(key_node, ast.Call)
            and isinstance(key_node.func, ast.Attribute)
            and key_node.func.attr == "isValid"
        ):
            field = ir.IsValid(header_ref=_ast_to_field_access(key_node.func.value))
        else:
            field = _ast_to_field_access(key_node)
        # p4.exact → "exact"
        if isinstance(val_node, ast.Attribute):
            match_kind = val_node.attr
        else:
            raise ValueError(f"Unsupported match kind: {ast.dump(val_node)}")
        keys.append(ir.TableKey(field=field, match_kind=match_kind))
    return tuple(keys)


def _compile_const_entries(
    dict_node: ast.Dict,
) -> tuple[ir.ConstEntry, ...]:
    """Compile const_entries = {value: action(args), ...} into ConstEntry nodes."""
    entries = []
    for key_node, val_node in zip(dict_node.keys, dict_node.values, strict=True):
        if key_node is None or (
            isinstance(key_node, ast.Constant) and key_node.value is None
        ):
            values = (ir.Wildcard(),)
        elif isinstance(key_node, ast.Tuple):
            values = tuple(_ast_to_expression(elt) for elt in key_node.elts)
        else:
            values = (_ast_to_expression(key_node),)

        if isinstance(val_node, ast.Call) and isinstance(val_node.func, ast.Name):
            action_name = val_node.func.id
            action_args = tuple(_ast_to_expression(a) for a in val_node.args)
        else:
            raise ValueError(f"Unsupported const_entries value: {ast.dump(val_node)}")
        entries.append(
            ir.ConstEntry(
                values=values, action_name=action_name, action_args=action_args
            )
        )
    return tuple(entries)


def _compile_implementation(node: ast.expr) -> str:
    """Compile implementation = hash_table(64) into a string like 'hash_table(64)'."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        name = node.func.attr
        if node.args and isinstance(node.args[0], ast.Constant):
            return f"{name}({node.args[0].value})"
        return name
    raise ValueError(f"Unsupported implementation: {ast.dump(node)}")


# --- Deparser compilation ---


def _compile_deparser(spec) -> ir.DeparserDecl:
    """Compile a @p4.deparser spec into a DeparserDecl."""
    func_def = _parse_spec_ast(spec)
    emit_order = []
    for node in func_def.body:
        if isinstance(node, ast.Pass):
            continue
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            if isinstance(call.func, ast.Attribute) and call.func.attr == "emit":
                arg = _ast_to_field_access(call.args[0])
                emit_order.append(arg)
                continue
        raise ValueError(f"Deparser only supports pkt.emit() calls: {ast.dump(node)}")
    return ir.DeparserDecl(
        name=spec._p4_name,
        emit_order=tuple(emit_order),
        param_names=_param_names_ordered(func_def),
    )

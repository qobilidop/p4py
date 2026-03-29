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

    return ir.Package(
        arch=arch,
        headers=headers_ir,
        structs=structs_ir,
        blocks=tuple(blocks),
    )


def _compile_types(headers_struct: type) -> tuple[ir.HeaderType, ...]:
    """Extract HeaderType IR nodes from a headers struct class."""
    result = []
    for _, header_cls in headers_struct._p4_members:
        fields = tuple(
            ir.HeaderField(name, ir.BitType(bt.width))
            for name, bt in header_cls._p4_fields
        )
        result.append(ir.HeaderType(name=header_cls._p4_name, fields=fields))
    return tuple(result)


def _compile_structs(pipeline) -> tuple[ir.StructType, ...]:
    """Compile struct types to IR."""
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
            if hasattr(ann, "width"):
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


def _ast_to_statement(node: ast.stmt, params: set[str]) -> ir.Statement:
    """Convert an AST statement to an IR Statement."""
    # Assignment: target = value
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        target = _ast_to_field_access(node.targets[0])
        value = _ast_to_expression(node.value)
        return ir.Assignment(target=target, value=value)

    # Expression statement (method call, function call, etc.)
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        return _ast_call_to_statement(node.value, params)

    # If/else
    if isinstance(node, ast.If):
        condition = _ast_to_expression(node.test)
        if not isinstance(condition, ir.IsValid):
            raise ValueError("if conditions must be hdr.x.isValid()")
        then_body = tuple(
            s for n in node.body if (s := _ast_to_statement(n, params)) is not None
        )
        else_body = tuple(
            s for n in node.orelse if (s := _ast_to_statement(n, params)) is not None
        )
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


def _ast_call_to_statement(call: ast.Call, params: set[str]) -> ir.Statement:
    """Convert an AST Call to a Statement (MethodCall, FunctionCall, etc.)."""
    # obj.method(args) — e.g., pkt.extract(hdr.ethernet)
    if isinstance(call.func, ast.Attribute):
        attr = call.func
        # table.apply()
        if attr.attr == "apply" and isinstance(attr.value, ast.Name):
            return ir.TableApply(table_name=attr.value.id)
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
                args = tuple(_ast_to_expression(a) for a in call.args)
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
        # Value case: case 0x0800
        elif isinstance(case.pattern, ast.MatchValue):
            if isinstance(case.pattern.value, ast.Constant):
                value = case.pattern.value.value
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

    for node in func_def.body:
        # @p4.action decorated function → ActionDecl
        if isinstance(node, ast.FunctionDef) and _has_p4_decorator(node, "action"):
            actions.append(_compile_action(node, params))
        # name = p4.table(...) → TableDecl
        elif isinstance(node, ast.Assign) and _is_table_call(node):
            tables.append(_compile_table(node))
        # pass statement — skip
        elif isinstance(node, ast.Pass):
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
    )


def _has_p4_decorator(node: ast.FunctionDef, name: str) -> bool:
    """Check if a function has a @p4.<name> decorator."""
    for dec in node.decorator_list:
        if isinstance(dec, ast.Attribute) and dec.attr == name:
            return True
    return False


def _compile_action(func_def: ast.FunctionDef, block_params: set[str]) -> ir.ActionDecl:
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
        if (s := _ast_to_statement(node, block_params)) is not None
    )
    return ir.ActionDecl(name=func_def.name, params=tuple(action_params), body=body)


def _is_table_call(node: ast.Assign) -> bool:
    """Check if an assignment is name = p4.table(...)."""
    if not isinstance(node.value, ast.Call):
        return False
    func = node.value.func
    return isinstance(func, ast.Attribute) and func.attr == "table"


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
    )


def _compile_table_keys(dict_node: ast.Dict) -> tuple[ir.TableKey, ...]:
    """Compile a dict literal {field: match_kind} into TableKeys."""
    keys = []
    for key_node, val_node in zip(dict_node.keys, dict_node.values, strict=True):
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
        if key_node is None:
            values = (ir.Wildcard(),)
        elif isinstance(key_node, ast.Constant) and key_node.value is None:
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

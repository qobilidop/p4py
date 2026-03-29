"""Compiles P4Mini language specs into IR nodes.

Parses Python AST from captured function sources and produces IR Program.
"""

from __future__ import annotations

import ast

from p4py.arch.v1model import V1Switch
from p4py.ir import nodes


def compile(pipeline: V1Switch) -> nodes.Program:
    """Compile a V1Switch pipeline into an IR Program."""
    headers_ir = _compile_types(pipeline.headers)
    structs_ir = _compile_structs(pipeline.headers, pipeline.metadata)
    parser_ir = _compile_parser(pipeline.parser)
    ingress_ir = _compile_control(pipeline.ingress)
    egress_ir = _compile_control(pipeline.egress) if pipeline.egress else None
    verify_ir = (
        _compile_checksum_control(pipeline.verify_checksum)
        if pipeline.verify_checksum
        else None
    )
    compute_ir = (
        _compile_checksum_control(pipeline.compute_checksum)
        if pipeline.compute_checksum
        else None
    )
    deparser_ir = _compile_deparser(pipeline.deparser)
    return nodes.Program(
        headers=headers_ir,
        structs=structs_ir,
        parser=parser_ir,
        ingress=ingress_ir,
        deparser=deparser_ir,
        egress=egress_ir,
        verify_checksum=verify_ir,
        compute_checksum=compute_ir,
    )


def _compile_types(headers_struct: type) -> tuple[nodes.HeaderType, ...]:
    """Extract HeaderType IR nodes from a headers struct class."""
    result = []
    for _, header_cls in headers_struct._p4_members:
        fields = tuple(
            nodes.HeaderField(name, nodes.BitType(bt.width))
            for name, bt in header_cls._p4_fields
        )
        result.append(nodes.HeaderType(name=header_cls._p4_name, fields=fields))
    return tuple(result)


def _compile_structs(
    headers_struct: type, metadata_struct: type
) -> tuple[nodes.StructType, ...]:
    """Compile struct types to IR."""
    from p4py.lang._types import struct as p4_struct

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
                members.append(nodes.StructMember(name, nodes.BitType(ann.width)))
            else:
                members.append(nodes.StructMember(name, ann._p4_name))
        result.append(nodes.StructType(name=s._p4_name, members=tuple(members)))
        seen.add(s._p4_name)

    for s in (headers_struct, metadata_struct):
        _compile_one(s)
    return tuple(result)


def _parse_spec_ast(spec) -> ast.FunctionDef:
    """Parse a spec's source into a FunctionDef AST node."""
    tree = ast.parse(spec._p4_source)
    # The source is a decorated function; find the FunctionDef.
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == spec._p4_name:
            return node
    raise ValueError(f"Could not find function '{spec._p4_name}' in source")


def _ast_to_field_access(node: ast.expr) -> nodes.FieldAccess:
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
    return nodes.FieldAccess(path=tuple(reversed(parts)))


def _ast_to_expression(node: ast.expr) -> nodes.Expression:
    """Convert an AST expression to an IR Expression."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return nodes.IntLiteral(value=node.value)
    if isinstance(node, (ast.Attribute, ast.Name)):
        return _ast_to_field_access(node)
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            op = "+"
        elif isinstance(node.op, ast.Sub):
            op = "-"
        else:
            raise ValueError(f"Unsupported arithmetic operator: {ast.dump(node.op)}")
        return nodes.ArithOp(
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
        return nodes.IsValid(header_ref=header_ref)
    raise ValueError(f"Unsupported expression: {ast.dump(node)}")


def _ast_to_statement(node: ast.stmt, params: set[str]) -> nodes.Statement:
    """Convert an AST statement to an IR Statement."""
    # Assignment: target = value
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        target = _ast_to_field_access(node.targets[0])
        value = _ast_to_expression(node.value)
        return nodes.Assignment(target=target, value=value)

    # Expression statement (method call, function call, etc.)
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        return _ast_call_to_statement(node.value, params)

    # If/else
    if isinstance(node, ast.If):
        condition = _ast_to_expression(node.test)
        if not isinstance(condition, nodes.IsValid):
            raise ValueError("if conditions must be hdr.x.isValid()")
        then_body = tuple(
            s for n in node.body if (s := _ast_to_statement(n, params)) is not None
        )
        else_body = tuple(
            s for n in node.orelse if (s := _ast_to_statement(n, params)) is not None
        )
        return nodes.IfElse(
            condition=condition, then_body=then_body, else_body=else_body
        )

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
                        nodes.SwitchActionCase(action_name=action_name, body=body)
                    )
            return nodes.SwitchAction(table_name=table_name, cases=tuple(cases))

    # pass → empty body (e.g., no-op actions)
    if isinstance(node, ast.Pass):
        return None

    raise ValueError(f"Unsupported statement: {ast.dump(node)}")


def _ast_call_to_statement(call: ast.Call, params: set[str]) -> nodes.Statement:
    """Convert an AST Call to a Statement (MethodCall, FunctionCall, etc.)."""
    # obj.method(args) — e.g., pkt.extract(hdr.ethernet)
    if isinstance(call.func, ast.Attribute):
        attr = call.func
        # table.apply()
        if attr.attr == "apply" and isinstance(attr.value, ast.Name):
            return nodes.TableApply(table_name=attr.value.id)
        # Module-qualified function: name.func(args) where name is not a
        # block parameter (e.g. v1model.mark_to_drop).  Strip the module
        # prefix and emit a plain FunctionCall.
        if isinstance(attr.value, ast.Name) and attr.value.id not in params:
            args = tuple(_ast_to_expression(a) for a in call.args)
            return nodes.FunctionCall(name=attr.attr, args=args)
        obj = _ast_to_field_access(attr.value)
        args = tuple(_ast_to_expression(a) for a in call.args)
        return nodes.MethodCall(object=obj, method=attr.attr, args=args)

    # free_function(args) — e.g., mark_to_drop(std_meta), drop()
    if isinstance(call.func, ast.Name):
        args = tuple(_ast_to_expression(a) for a in call.args)
        return nodes.FunctionCall(name=call.func.id, args=args)

    raise ValueError(f"Unsupported call: {ast.dump(call)}")


# --- Parser compilation ---


def _param_names(func_def: ast.FunctionDef) -> set[str]:
    """Extract parameter names from a FunctionDef."""
    return {arg.arg for arg in func_def.args.args}


def _compile_parser(spec) -> nodes.ParserDecl:
    """Compile a @p4.parser spec into a ParserDecl."""
    func_def = _parse_spec_ast(spec)
    params = _param_names(func_def)
    states = []
    for node in func_def.body:
        if isinstance(node, ast.FunctionDef):
            states.append(_compile_parser_state(node, params))
    return nodes.ParserDecl(name=spec._p4_name, states=tuple(states))


def _compile_parser_state(
    func_def: ast.FunctionDef, params: set[str]
) -> nodes.ParserState:
    """Compile a nested function into a ParserState."""
    body_stmts: list[nodes.Statement] = []
    transition: nodes.Transition | nodes.TransitionSelect | None = None

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
    return nodes.ParserState(
        name=func_def.name,
        body=tuple(body_stmts),
        transition=transition,
    )


def _compile_transition(ret: ast.Return) -> nodes.Transition:
    """Compile a return statement to a Transition."""
    if isinstance(ret.value, ast.Name):
        return nodes.Transition(next_state=ret.value.id)
    if isinstance(ret.value, ast.Attribute):
        # p4.ACCEPT, p4.REJECT
        return nodes.Transition(next_state=ret.value.attr.lower())
    if isinstance(ret.value, ast.Constant) and isinstance(ret.value.value, str):
        return nodes.Transition(next_state=ret.value.value)
    raise ValueError(f"Unsupported transition: {ast.dump(ret)}")


def _compile_transition_select(match: ast.Match) -> nodes.TransitionSelect:
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
        cases.append(nodes.SelectCase(value=value, next_state=transition.next_state))

    return nodes.TransitionSelect(field=field, cases=tuple(cases))


# --- Control compilation ---


def _compile_control(spec) -> nodes.ControlDecl:
    """Compile a @p4.control spec into a ControlDecl."""
    func_def = _parse_spec_ast(spec)
    params = _param_names(func_def)

    actions: list[nodes.ActionDecl] = []
    tables: list[nodes.TableDecl] = []
    apply_body: list[nodes.Statement] = []

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

    return nodes.ControlDecl(
        name=spec._p4_name,
        actions=tuple(actions),
        tables=tuple(tables),
        apply_body=tuple(apply_body),
    )


def _has_p4_decorator(node: ast.FunctionDef, name: str) -> bool:
    """Check if a function has a @p4.<name> decorator."""
    for dec in node.decorator_list:
        if isinstance(dec, ast.Attribute) and dec.attr == name:
            return True
    return False


def _compile_action(
    func_def: ast.FunctionDef, block_params: set[str]
) -> nodes.ActionDecl:
    """Compile a @p4.action function into an ActionDecl."""
    action_params = []
    for arg in func_def.args.args:
        if arg.annotation is not None:
            # p4.bit(W) → BitType
            if (
                isinstance(arg.annotation, ast.Call)
                and isinstance(arg.annotation.func, ast.Attribute)
                and arg.annotation.func.attr == "bit"
            ):
                width = arg.annotation.args[0].value
                action_params.append(
                    nodes.ActionParam(name=arg.arg, type=nodes.BitType(width))
                )
            else:
                raise ValueError(
                    f"Action param '{arg.arg}' must be annotated with p4.bit(W)"
                )

    body = tuple(
        s
        for node in func_def.body
        if (s := _ast_to_statement(node, block_params)) is not None
    )
    return nodes.ActionDecl(name=func_def.name, params=tuple(action_params), body=body)


def _is_table_call(node: ast.Assign) -> bool:
    """Check if an assignment is name = p4.table(...)."""
    if not isinstance(node.value, ast.Call):
        return False
    func = node.value.func
    return isinstance(func, ast.Attribute) and func.attr == "table"


def _compile_table(node: ast.Assign) -> nodes.TableDecl:
    """Compile name = p4.table(...) into a TableDecl."""
    name = node.targets[0].id
    call = node.value

    keys = ()
    actions = ()
    default_action = ""
    default_action_args: tuple[nodes.Expression, ...] = ()

    for kw in call.keywords:
        if kw.arg == "key":
            keys = _compile_table_keys(kw.value)
        elif kw.arg == "actions":
            actions = tuple(elt.id for elt in kw.value.elts)
        elif kw.arg == "default_action":
            if isinstance(kw.value, ast.Name):
                default_action = kw.value.id
            elif isinstance(kw.value, ast.Call):
                default_action = kw.value.func.id
                default_action_args = tuple(
                    _ast_to_expression(a) for a in kw.value.args
                )

    return nodes.TableDecl(
        name=name,
        keys=keys,
        actions=actions,
        default_action=default_action,
        default_action_args=default_action_args,
    )


def _compile_table_keys(dict_node: ast.Dict) -> tuple[nodes.TableKey, ...]:
    """Compile a dict literal {field: match_kind} into TableKeys."""
    keys = []
    for key_node, val_node in zip(dict_node.keys, dict_node.values, strict=True):
        field = _ast_to_field_access(key_node)
        # p4.exact → "exact"
        if isinstance(val_node, ast.Attribute):
            match_kind = val_node.attr
        else:
            raise ValueError(f"Unsupported match kind: {ast.dump(val_node)}")
        keys.append(nodes.TableKey(field=field, match_kind=match_kind))
    return tuple(keys)


# --- Checksum control compilation ---


def _compile_checksum_control(spec) -> nodes.ControlDecl:
    """Compile a checksum control (verify_checksum or compute_checksum)."""
    func_def = _parse_spec_ast(spec)
    params = _param_names(func_def)
    apply_body: list[nodes.Statement] = []

    for node in func_def.body:
        if isinstance(node, ast.Pass):
            continue
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            stmt = _compile_checksum_call(node.value)
            if stmt is not None:
                apply_body.append(stmt)
                continue
        apply_body.append(_ast_to_statement(node, params))

    return nodes.ControlDecl(
        name=spec._p4_name,
        actions=(),
        tables=(),
        apply_body=tuple(apply_body),
    )


def _compile_checksum_call(
    call: ast.Call,
) -> nodes.ChecksumVerify | nodes.ChecksumUpdate | None:
    """Try to compile a function call as a checksum extern."""
    if not isinstance(call.func, ast.Attribute):
        return None
    func_name = call.func.attr
    if func_name not in ("verify_checksum", "update_checksum"):
        return None

    # Parse keyword arguments.
    kwargs: dict[str, ast.expr] = {}
    for kw in call.keywords:
        kwargs[kw.arg] = kw.value

    condition = _ast_to_expression(kwargs["condition"])
    checksum = _ast_to_field_access(kwargs["checksum"])

    # data is a list of field accesses.
    data_node = kwargs["data"]
    if isinstance(data_node, ast.List):
        data = tuple(_ast_to_field_access(elt) for elt in data_node.elts)
    else:
        raise ValueError(f"Checksum data must be a list literal: {ast.dump(data_node)}")

    # algo is v1model.HashAlgorithm.csum16 → extract the final attribute name.
    algo_node = kwargs["algo"]
    if isinstance(algo_node, ast.Attribute):
        algo = algo_node.attr
    else:
        raise ValueError(f"Unsupported algo: {ast.dump(algo_node)}")

    if func_name == "verify_checksum":
        return nodes.ChecksumVerify(
            condition=condition, data=data, checksum=checksum, algo=algo
        )
    else:
        return nodes.ChecksumUpdate(
            condition=condition, data=data, checksum=checksum, algo=algo
        )


# --- Deparser compilation ---


def _compile_deparser(spec) -> nodes.DeparserDecl:
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
    return nodes.DeparserDecl(name=spec._p4_name, emit_order=tuple(emit_order))

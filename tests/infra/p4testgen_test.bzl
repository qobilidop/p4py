"""Bazel macro for p4testgen tests of P4Py programs."""

load("@rules_python//python:defs.bzl", "py_test")

def p4testgen_test(name, p4_module, p4_library, **kwargs):
    """Define a py_test that runs p4testgen-generated tests through the simulator.

    Args:
        name: Test target name.
        p4_module: Dotted Python module path containing a `main` function.
        p4_library: Label for the py_library containing the P4Py program.
        **kwargs: Additional args passed to py_test.
    """
    tags = kwargs.pop("tags", [])
    if "e2e" not in tags:
        tags = tags + ["e2e"]

    py_test(
        name = name,
        srcs = ["//tests/infra:p4testgen_runner.py"],
        main = "p4testgen_runner.py",
        data = [
            "@p4c//backends/p4tools:p4testgen",
            "@p4c//:p4include",
        ],
        args = [
            p4_module,
            "$(rootpath @p4c//backends/p4tools:p4testgen)",
        ],
        deps = [
            p4_library,
            "//tests/infra:p4testgen_runner",
        ],
        tags = tags,
        timeout = "moderate",
        **kwargs
    )

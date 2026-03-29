"""Bazel macro for golden tests of P4Py programs."""

load("@rules_python//python:defs.bzl", "py_test")

def golden_test(name, p4_module, p4_library, golden_file, **kwargs):
    """Define a py_test that compares emitted P4 against a golden file.

    Args:
        name: Test target name.
        p4_module: Dotted Python module path containing a `main` function.
        p4_library: Label for the py_library containing the P4Py program.
        golden_file: Label for the golden .p4 file.
        **kwargs: Additional args passed to py_test.
    """
    tags = kwargs.pop("tags", [])
    if "e2e" not in tags:
        tags = tags + ["e2e"]

    py_test(
        name = name,
        srcs = ["//tests/infra:golden_runner.py"],
        main = "golden_runner.py",
        data = [golden_file],
        args = [
            p4_module,
            "$(rootpath " + golden_file + ")",
        ],
        deps = [
            p4_library,
            "//tests/infra:golden_runner",
        ],
        tags = tags,
        timeout = "short",
        **kwargs
    )

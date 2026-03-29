"""Bazel macro for STF tests against the P4Py simulator."""

load("@rules_python//python:defs.bzl", "py_test")

def stf_test(name, p4_module, stf_file, p4_library, **kwargs):
    """Define a py_test that runs an STF test through the P4Py simulator.

    Args:
        name: Test target name.
        p4_module: Dotted Python module path containing a `main` function
            (e.g. "tests.e2e.examples.basic_forward.basic_forward").
        stf_file: Label for the .stf file.
        p4_library: Label for the py_library containing the P4Py program.
        **kwargs: Additional args passed to py_test.
    """
    tags = kwargs.pop("tags", [])
    if "e2e" not in tags:
        tags = tags + ["e2e"]

    py_test(
        name = name,
        srcs = ["//tests/infra:stf_sim_runner.py"],
        main = "stf_sim_runner.py",
        data = [stf_file],
        args = [
            p4_module,
            "$(rootpath " + stf_file + ")",
        ],
        deps = [
            p4_library,
            "//tests/infra:stf_sim_runner",
        ],
        tags = tags,
        timeout = "short",
        **kwargs
    )

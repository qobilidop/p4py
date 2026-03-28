"""Bazel macro for STF tests against BMv2."""

load("@rules_python//python:defs.bzl", "py_test")

def stf_test(name, p4_program, stf_file, **kwargs):
    """Define a py_test that runs an STF test against BMv2.

    Args:
        name: Test target name.
        p4_program: Label for the .p4 file.
        stf_file: Label for the .stf file.
        **kwargs: Additional args passed to py_test.
    """
    tags = kwargs.pop("tags", [])
    if "e2e" not in tags:
        tags = tags + ["e2e"]

    # Run locally (no sandbox) because the test needs sudo for veth pairs
    # and access to system tools (p4c, simple_switch, simple_switch_CLI).
    py_test(
        name = name,
        srcs = ["//tests/infra:stf_runner.py"],
        main = "stf_runner.py",
        data = [p4_program, stf_file],
        args = [
            "$(rootpath " + p4_program + ")",
            "$(rootpath " + stf_file + ")",
        ],
        deps = ["//tests/infra:stf_runner"],
        tags = tags + ["local"],
        local = True,
        timeout = "short",
        **kwargs
    )

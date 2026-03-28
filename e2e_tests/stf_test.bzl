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

    py_test(
        name = name,
        srcs = ["//e2e_tests:stf_runner.py"],
        main = "stf_runner.py",
        data = [p4_program, stf_file],
        args = [
            "$(rootpath " + p4_program + ")",
            "$(rootpath " + stf_file + ")",
        ],
        deps = ["//e2e_tests:stf_runner"],
        tags = tags,
        **kwargs
    )

"""Sphinx configuration for P4Py."""

project = "P4Py"
copyright = "2026, P4Py Contributors"
author = "P4Py Contributors"

extensions = [
    "myst_parser",
]

myst_enable_extensions = [
    "colon_fence",
    "deflist",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "superpowers"]

html_theme = "furo"
html_title = "P4Py"

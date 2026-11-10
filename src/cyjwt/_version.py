"""Single source of truth for the package version.

Read statically by setuptools (``[tool.setuptools.dynamic]``), so it must stay a
plain literal assignment.
"""

__version__ = "0.2.0"

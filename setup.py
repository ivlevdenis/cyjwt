"""Build script: cythonize the compiled modules.

Metadata lives in ``pyproject.toml``; this file exists only to declare the
``Extension`` objects, because the extension module name (``cyjwt._core``) must
not be derived from its physical path (``src/cyjwt/_core.pyx``).
"""

from Cython.Build import cythonize
from setuptools import Extension, setup

COMPILER_DIRECTIVES = {
    "language_level": "3",
    "binding": True,  # keep signature introspection for the public def functions
    "embedsignature": True,
}

EXTENSIONS = [
    Extension(
        name="cyjwt._core",
        sources=["src/cyjwt/_core.pyx"],
        # No third-party C headers are used (typed memoryviews only), so the
        # build has no data-layer dependencies.
    ),
]

setup(
    ext_modules=cythonize(
        EXTENSIONS,
        compiler_directives=COMPILER_DIRECTIVES,
        # Do not commit generated C: it is a build artifact, and sdist regenerates it.
    ),
)

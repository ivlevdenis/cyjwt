"""C-level declarations exposed to other Cython modules.

Keep in sync with ``_core.pyx`` and ``_core.pyi``.
"""

cdef bint ct_equal(
    const unsigned char* a, const unsigned char* b, Py_ssize_t n
) noexcept nogil

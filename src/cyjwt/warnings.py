"""Warning types, mirroring ``jwt.warnings``."""

from __future__ import annotations


class RemovedInPyjwt3Warning(DeprecationWarning):
    """Warning for features that will be removed in PyJWT 3."""


class InsecureKeyLengthWarning(UserWarning):
    """Warning emitted when a cryptographic key is shorter than the minimum
    recommended length (see RFC 7518 §3.2)."""

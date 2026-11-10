"""Exception hierarchy, API-compatible with PyJWT 2.x for the HS* subset."""

from __future__ import annotations


class PyJWTError(Exception):
    """Base class for all exceptions."""


class InvalidTokenError(PyJWTError):
    pass


class DecodeError(InvalidTokenError):
    pass


class InvalidSignatureError(DecodeError):
    pass


class ExpiredSignatureError(InvalidTokenError):
    pass


class InvalidAudienceError(InvalidTokenError):
    pass


class InvalidIssuerError(InvalidTokenError):
    pass


class InvalidIssuedAtError(InvalidTokenError):
    pass


class ImmatureSignatureError(InvalidTokenError):
    pass


class InvalidKeyError(PyJWTError):
    pass


class InvalidAlgorithmError(InvalidTokenError):
    pass


class MissingRequiredClaimError(InvalidTokenError):
    def __init__(self, claim: str) -> None:
        self.claim = claim

    def __str__(self) -> str:
        return f'Token is missing the "{self.claim}" claim'


class InvalidSubjectError(InvalidTokenError):
    pass


class InvalidJTIError(InvalidTokenError):
    pass


__all__ = [
    "DecodeError",
    "ExpiredSignatureError",
    "ImmatureSignatureError",
    "InvalidAlgorithmError",
    "InvalidAudienceError",
    "InvalidIssuedAtError",
    "InvalidIssuerError",
    "InvalidJTIError",
    "InvalidKeyError",
    "InvalidSignatureError",
    "InvalidSubjectError",
    "InvalidTokenError",
    "MissingRequiredClaimError",
    "PyJWTError",
]

"""cyjwt: a fast, dependency-free reimplementation of PyJWT's HS* subset.

Public API mirrors ``jwt`` (PyJWT) for HS256/HS384/HS512 tokens:
``encode``, ``decode``, ``decode_complete``, ``PyJWT``, ``PyJWS``,
``get_unverified_header``, ``register_algorithm`` and the exception hierarchy.

Asymmetric algorithms (RS*/ES*/PS*/EdDSA) are not built in; register a custom
``Algorithm`` (e.g. one wrapping ``cryptography``) if you need them.
"""

from ._version import __version__
from .api_jws import (
    PyJWS,
    get_algorithm_by_name,
    get_unverified_header,
    register_algorithm,
    unregister_algorithm,
)
from .api_jwt import PyJWT, decode, decode_complete, encode
from .exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidJTIError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidSubjectError,
    InvalidTokenError,
    MissingRequiredClaimError,
    PyJWTError,
)
from .warnings import InsecureKeyLengthWarning, RemovedInPyjwt3Warning

__all__ = [
    "DecodeError",
    "ExpiredSignatureError",
    "ImmatureSignatureError",
    "InsecureKeyLengthWarning",
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
    "PyJWS",
    "PyJWT",
    "PyJWTError",
    "RemovedInPyjwt3Warning",
    "__version__",
    "decode",
    "decode_complete",
    "encode",
    "get_algorithm_by_name",
    "get_unverified_header",
    "register_algorithm",
    "unregister_algorithm",
]

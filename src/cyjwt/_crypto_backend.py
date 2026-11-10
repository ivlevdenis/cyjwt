"""All ``cryptography`` imports for the asymmetric algorithms live here.

Keeping them in one module means ``import cyjwt`` stays dependency-free: if
``cryptography`` is missing, importing this module raises ``ImportError`` and
:mod:`cyjwt.algorithms` falls back to the HMAC/none algorithms.

Install the extra with ``pip install cyjwt[crypto]``.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256K1,
    SECP256R1,
    SECP384R1,
    SECP521R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PrivateKey,
    Ed448PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import (
    load_der_public_key,
    load_pem_private_key,
    load_pem_public_key,
    load_ssh_public_key,
)

__all__ = [
    "ECDSA",
    "InvalidSignature",
    "UnsupportedAlgorithm",
    "curve_class",
    "der_to_raw_signature",
    "ec_key_types",
    "hashes",
    "is_der_key",
    "load_pem_private_key",
    "load_pem_public_key",
    "load_ssh_public_key",
    "okp_key_types",
    "padding",
    "raw_to_der_signature",
    "rsa_key_types",
]


def rsa_key_types() -> tuple[type, ...]:
    return (RSAPrivateKey, RSAPublicKey)


def ec_key_types() -> tuple[type, ...]:
    return (EllipticCurvePrivateKey, EllipticCurvePublicKey)


def okp_key_types() -> tuple[type, ...]:
    return (Ed25519PrivateKey, Ed25519PublicKey, Ed448PrivateKey, Ed448PublicKey)


_CURVES: dict[str, type] = {
    "secp256r1": SECP256R1,
    "secp256k1": SECP256K1,
    "secp384r1": SECP384R1,
    "secp521r1": SECP521R1,
}


def curve_class(name: str) -> type:
    """Resolve a curve name to its ``cryptography`` class."""
    try:
        return _CURVES[name]
    except KeyError:
        raise ValueError(f"Unsupported curve: {name}") from None


def is_der_key(key: bytes) -> bool:
    """Return True when ``key`` is a DER public key or DER x509 certificate.

    Both loaders signal "not this format" with one of the caught exceptions;
    that is their documented contract, so continuing to the next probe is the
    intended control flow rather than swallowed failure.
    """
    for loader in (load_der_public_key, x509.load_der_x509_certificate):
        try:
            loader(key)
        except (TypeError, ValueError, UnsupportedAlgorithm):
            continue
        return True
    return False


def der_to_raw_signature(der_sig: bytes, key_size: int) -> bytes:
    """Convert a DER ECDSA signature into the fixed-width ``r || s`` form (JWS)."""
    num_bytes = (key_size + 7) // 8
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(num_bytes, "big") + s.to_bytes(num_bytes, "big")


def raw_to_der_signature(raw_sig: bytes, key_size: int) -> bytes:
    """Convert a JWS ``r || s`` signature into DER for ``cryptography``."""
    num_bytes = (key_size + 7) // 8
    if len(raw_sig) != 2 * num_bytes:
        raise ValueError("Invalid signature")
    r = int.from_bytes(raw_sig[:num_bytes], "big")
    s = int.from_bytes(raw_sig[num_bytes:], "big")
    return encode_dss_signature(r, s)

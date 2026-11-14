"""Differential tests: ``prepare_key`` verdicts against the real PyJWT.

The same key bytes go through both implementations; the outcome (accept or the
exception class name) must match. Covers PEM, SSH, DER, x509 certificates, JWK
documents, malformed input and non-bytes keys.

Skipped when PyJWT or ``cryptography`` is unavailable.
"""

from __future__ import annotations

import datetime
from collections.abc import Iterator
from typing import Any

import pytest

jwt = pytest.importorskip("jwt")
crypto = pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

import cyjwt  # noqa: E402

_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_EC_KEY = ec.generate_private_key(ec.SECP256R1())
_ED_KEY = ed25519.Ed25519PrivateKey.generate()


def _self_signed_cert() -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cyjwt-test")])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(_RSA_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    return builder.sign(_RSA_KEY, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _corpus() -> Iterator[tuple[str, Any]]:
    pem_private = _RSA_KEY.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    yield "raw 32-byte secret", b"x" * 32
    yield "raw 8-byte secret", b"shortkey"
    yield "unicode secret as str", "секрет" * 6
    yield "empty bytes", b""
    yield "empty str", ""
    yield "rsa pem private", pem_private
    yield (
        "rsa pem public",
        _RSA_KEY.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
    )
    yield (
        "rsa ssh public",
        _RSA_KEY.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        ),
    )
    yield (
        "rsa der public",
        _RSA_KEY.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
    )
    yield "x509 der certificate", _self_signed_cert()
    yield (
        "ec pem public",
        _EC_KEY.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
    )
    yield (
        "ed25519 pem public",
        _ED_KEY.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
    )
    yield "nested pem (whitespace/BOM prefix)", b"\xef\xbb\xbf  \n" + pem_private
    yield "jwk json oct", b'{"kty":"oct","k":"AAAA"}'
    yield "jwk json rsa", b'{"kty":"RSA","n":"AQAB","e":"AQAB"}'
    yield "jwk json nested in list", b'[{"kty":"oct"}]'
    yield "json without kty", b'{"hello":"world"}'
    yield "json array of scalars", b"[1,2,3]"
    yield "deeply nested json", b"[" * 200 + b'{"kty":"oct"}' + b"]" * 200
    yield "broken json", b'{"kty":'
    yield "ascii that looks like pem marker", b"-----BEGIN FOO-----"
    yield "pem begin, known label, no end", b"-----BEGIN PUBLIC KEY-----\nAAAA"
    yield "pem spaced separators", b"---- BEGIN CERTIFICATE ----\nAAAA\n---- END CERTIFICATE ----"
    yield "pem paired, garbage body", b"-----BEGIN PUBLIC KEY-----\nZZZZ\n-----END PUBLIC KEY-----"
    yield "pem end before begin", b"-----END PUBLIC KEY-----AAAA-----BEGIN PUBLIC KEY-----"
    yield "int instead of key", 42


def _verdict(module: Any, key: Any) -> str:
    """Return ``ok`` or the exception class name for one key."""
    try:
        module.api_jws.PyJWS().get_algorithm_by_name("HS256").prepare_key(key)
    except Exception as exc:  # the class name *is* the assertion
        return type(exc).__name__
    return "ok"


_CORPUS = list(_corpus())


@pytest.mark.parametrize("label,key", _CORPUS, ids=[label for label, _ in _CORPUS])
def test_prepare_key_matches_pyjwt(label: str, key: Any) -> None:
    ours = _verdict(cyjwt, key)
    theirs = _verdict(jwt, key)
    assert ours == theirs, f"{label}: cyjwt={ours} pyjwt={theirs}"


def test_der_verdict_is_stable_across_calls() -> None:
    """The memoised DER probe must return the same answer every time."""
    from cyjwt import _crypto_backend

    der = _RSA_KEY.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    plain = b"x" * 32
    first = (_crypto_backend.is_der_key(der), _crypto_backend.is_der_key(plain))
    second = (_crypto_backend.is_der_key(der), _crypto_backend.is_der_key(plain))
    assert first == second == (True, False)


def test_der_probe_accepts_bytes_like() -> None:
    """bytearray/memoryview keep working — no unhashable-input trap, no crash."""
    from cyjwt import _crypto_backend

    der = _RSA_KEY.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert _crypto_backend.is_der_key(bytearray(der)) is True
    assert _crypto_backend.is_der_key(memoryview(der)) is True
    assert _crypto_backend.is_der_key(bytearray(b"x" * 32)) is False

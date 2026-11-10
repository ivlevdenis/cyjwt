"""Asymmetric algorithm tests (skipped when ``cryptography`` is absent)."""

from __future__ import annotations

import warnings

import pytest

import cyjwt
from cyjwt import (
    InsecureKeyLengthWarning,
    InvalidKeyError,
    InvalidSignatureError,
    PyJWS,
    decode,
    encode,
    get_unverified_header,
)
from cyjwt.algorithms import get_default_algorithms

serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
ec = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ec")
ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
ed448 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed448")
UnsupportedAlgorithm = pytest.importorskip("cryptography.exceptions").UnsupportedAlgorithm

PAYLOAD = {"sub": "user", "iss": "cyjwt"}


def _private_pem(key: object) -> str:
    return key.private_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _public_pem(key: object) -> str:
    return (
        key.public_key()
        .public_bytes(  # type: ignore[attr-defined]
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )


@pytest.fixture(scope="module")
def rsa_key() -> object:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def rsa_small_key() -> object:
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


@pytest.fixture(scope="module")
def ec_keys() -> dict[str, object]:
    return {
        "ES256": ec.generate_private_key(ec.SECP256R1()),
        "ES384": ec.generate_private_key(ec.SECP384R1()),
        "ES512": ec.generate_private_key(ec.SECP521R1()),
    }


@pytest.fixture(scope="module")
def ed_keys() -> dict[str, object]:
    keys: dict[str, object] = {}
    try:
        keys["EdDSA-ed25519"] = ed25519.Ed25519PrivateKey.generate()
    except UnsupportedAlgorithm:  # pragma: no cover - depends on OpenSSL
        pytest.skip("Ed25519 not supported by this OpenSSL build")
    try:
        keys["EdDSA-ed448"] = ed448.Ed448PrivateKey.generate()
    except UnsupportedAlgorithm:  # pragma: no cover
        pytest.skip("Ed448 not supported by this OpenSSL build")
    return keys


class TestRegistry:
    def test_asymmetric_algorithms_registered(self) -> None:
        algorithms = get_default_algorithms()
        for name in (
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES256K",
            "ES384",
            "ES512",
            "ES521",
            "EdDSA",
        ):
            assert name in algorithms

    def test_algorithms_listed_by_jws(self) -> None:
        assert "RS256" in PyJWS().get_algorithms()


class TestRsa:
    @pytest.mark.parametrize("alg", ["RS256", "RS384", "RS512"])
    def test_roundtrip(self, alg: str, rsa_key: object) -> None:
        token = encode(PAYLOAD, _private_pem(rsa_key), algorithm=alg)
        assert get_unverified_header(token)["alg"] == alg
        assert decode(token, _public_pem(rsa_key), algorithms=[alg]) == PAYLOAD
        # A private key must work for verification as well.
        assert decode(token, _private_pem(rsa_key), algorithms=[alg]) == PAYLOAD

    @pytest.mark.parametrize("alg", ["PS256", "PS384", "PS512"])
    def test_pss_roundtrip(self, alg: str, rsa_key: object) -> None:
        token = encode(PAYLOAD, _private_pem(rsa_key), algorithm=alg)
        assert decode(token, _public_pem(rsa_key), algorithms=[alg]) == PAYLOAD

    def test_key_object_accepted(self, rsa_key: object) -> None:
        token = encode(PAYLOAD, rsa_key, algorithm="RS256")  # type: ignore[arg-type]
        assert decode(token, rsa_key.public_key(), algorithms=["RS256"]) == PAYLOAD  # type: ignore[attr-defined]

    def test_ssh_public_key_accepted(self, rsa_key: object) -> None:
        ssh_key = rsa_key.public_key().public_bytes(  # type: ignore[attr-defined]
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        )
        token = encode(PAYLOAD, rsa_key, algorithm="RS256")  # type: ignore[arg-type]
        assert decode(token, ssh_key, algorithms=["RS256"]) == PAYLOAD

    def test_tampered_signature(self, rsa_key: object) -> None:
        token = encode(PAYLOAD, _private_pem(rsa_key), algorithm="RS256")
        header, payload, signature = token.split(".")
        tampered = ".".join([header, payload, "A" + signature[1:]])
        with pytest.raises(InvalidSignatureError):
            decode(tampered, _public_pem(rsa_key), algorithms=["RS256"])

    def test_wrong_public_key(self, rsa_key: object) -> None:
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = encode(PAYLOAD, _private_pem(rsa_key), algorithm="RS256")
        with pytest.raises(InvalidSignatureError):
            decode(token, _public_pem(other), algorithms=["RS256"])

    def test_short_key_warns(self, rsa_small_key: object) -> None:
        with pytest.warns(InsecureKeyLengthWarning, match="RSA key is 1024 bits"):
            encode(PAYLOAD, _private_pem(rsa_small_key), algorithm="RS256")

    def test_short_key_can_be_enforced(self, rsa_small_key: object) -> None:
        jwt = cyjwt.PyJWT(options={"enforce_minimum_key_length": True})
        with pytest.raises(InvalidKeyError, match="RSA key is 1024 bits"):
            jwt.encode(PAYLOAD, _private_pem(rsa_small_key), algorithm="RS256")

    def test_invalid_pem(self) -> None:
        with pytest.raises(InvalidKeyError, match="Could not parse"):
            encode(PAYLOAD, "not a key", algorithm="RS256")

    def test_non_key_type(self) -> None:
        with pytest.raises(TypeError, match="PEM-formatted key"):
            encode(PAYLOAD, 123, algorithm="RS256")  # type: ignore[arg-type]


class TestEc:
    @pytest.mark.parametrize("alg", ["ES256", "ES384", "ES512"])
    def test_roundtrip(self, alg: str, ec_keys: dict[str, object]) -> None:
        key = ec_keys["ES512" if alg == "ES512" else alg]
        token = encode(PAYLOAD, _private_pem(key), algorithm=alg)
        assert get_unverified_header(token)["alg"] == alg
        assert decode(token, _public_pem(key), algorithms=[alg]) == PAYLOAD

    def test_es256k(self) -> None:
        try:
            key = ec.generate_private_key(ec.SECP256K1())
        except UnsupportedAlgorithm:  # pragma: no cover - OpenSSL dependent
            pytest.skip("secp256k1 not supported by this OpenSSL build")
        token = encode(PAYLOAD, _private_pem(key), algorithm="ES256K")
        assert decode(token, _public_pem(key), algorithms=["ES256K"]) == PAYLOAD

    def test_wrong_curve_rejected(self, ec_keys: dict[str, object]) -> None:
        # An ES256 token must not verify with a P-384 key under ES256.
        p384_pem = _private_pem(ec_keys["ES384"])
        with pytest.raises(InvalidKeyError, match="curve"):
            encode(PAYLOAD, p384_pem, algorithm="ES256")

    def test_wrong_key_family(self, ec_keys: dict[str, object]) -> None:
        # A key object of the wrong family is not PEM-like, so PyJWT (and we)
        # raise TypeError before any crypto-level type check.
        with pytest.raises(TypeError, match="PEM-formatted key"):
            encode(PAYLOAD, ec_keys["ES256"], algorithm="RS256")  # type: ignore[arg-type]

    def test_ssh_public_key_accepted(self, ec_keys: dict[str, object]) -> None:
        key = ec_keys["ES256"]
        ssh_key = key.public_key().public_bytes(  # type: ignore[attr-defined]
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        )
        token = encode(PAYLOAD, _private_pem(key), algorithm="ES256")
        assert decode(token, ssh_key, algorithms=["ES256"]) == PAYLOAD

    def test_truncated_signature_rejected(self, ec_keys: dict[str, object]) -> None:
        key = ec_keys["ES256"]
        token = encode(PAYLOAD, _private_pem(key), algorithm="ES256")
        header, payload, signature = token.split(".")
        truncated = ".".join([header, payload, signature[:20]])
        with pytest.raises(InvalidSignatureError):
            decode(truncated, _public_pem(key), algorithms=["ES256"])


class TestEdDsa:
    def test_ed25519_roundtrip(self, ed_keys: dict[str, object]) -> None:
        key = ed_keys["EdDSA-ed25519"]
        token = encode(PAYLOAD, _private_pem(key), algorithm="EdDSA")
        assert decode(token, _public_pem(key), algorithms=["EdDSA"]) == PAYLOAD

    def test_ed448_roundtrip(self, ed_keys: dict[str, object]) -> None:
        key = ed_keys["EdDSA-ed448"]
        token = encode(PAYLOAD, _private_pem(key), algorithm="EdDSA")
        assert decode(token, _public_pem(key), algorithms=["EdDSA"]) == PAYLOAD

    def test_ssh_public_key_accepted(self, ed_keys: dict[str, object]) -> None:
        key = ed_keys["EdDSA-ed25519"]
        ssh_key = key.public_key().public_bytes(  # type: ignore[attr-defined]
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        )
        token = encode(PAYLOAD, _private_pem(key), algorithm="EdDSA")
        assert decode(token, ssh_key, algorithms=["EdDSA"]) == PAYLOAD

    def test_unrelated_key_rejected(self, ed_keys: dict[str, object]) -> None:
        token = encode(PAYLOAD, _private_pem(ed_keys["EdDSA-ed25519"]), algorithm="EdDSA")
        other = ed448.Ed448PrivateKey.generate()
        with pytest.raises(InvalidSignatureError):
            decode(token, _public_pem(other), algorithms=["EdDSA"])


class TestHmacDerRejection:
    def test_der_public_key_cannot_be_hmac_secret(self, rsa_key: object) -> None:
        der = rsa_key.public_key().public_bytes(  # type: ignore[attr-defined]
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with pytest.raises(InvalidKeyError, match="asymmetric key"):
            encode({"a": 1}, der)

    def test_warning_is_not_raised_for_good_keys(self, rsa_key: object) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            encode(PAYLOAD, _private_pem(rsa_key), algorithm="RS256")

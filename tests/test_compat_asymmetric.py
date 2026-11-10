"""Differential tests for the asymmetric algorithms against PyJWT.

Skipped unless both ``pyjwt`` and ``cryptography`` are installed.
"""

from __future__ import annotations

import warnings

import pytest

jwt = pytest.importorskip("jwt")
import cyjwt  # noqa: E402

serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
ec = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ec")
ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")

PAYLOAD = {"sub": "parity", "iss": "cyjwt"}


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
def ec_key() -> object:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="module")
def ed_key() -> object:
    return ed25519.Ed25519PrivateKey.generate()


class TestDeterministicTokens:
    """RSASSA-PKCS1-v1_5 and EdDSA are deterministic, so tokens must match."""

    @pytest.mark.parametrize("alg", ["RS256", "RS384", "RS512"])
    def test_rsa_tokens_identical(self, alg: str, rsa_key: object) -> None:
        ours = cyjwt.encode(PAYLOAD, _private_pem(rsa_key), algorithm=alg)
        theirs = jwt.encode(PAYLOAD, _private_pem(rsa_key), algorithm=alg)
        assert ours == theirs

    def test_eddsa_tokens_identical(self, ed_key: object) -> None:
        ours = cyjwt.encode(PAYLOAD, _private_pem(ed_key), algorithm="EdDSA")
        theirs = jwt.encode(PAYLOAD, _private_pem(ed_key), algorithm="EdDSA")
        assert ours == theirs

    @pytest.mark.parametrize("alg", ["RS256", "EdDSA"])
    def test_mutual_decode(self, alg: str, rsa_key: object, ed_key: object) -> None:
        key = rsa_key if alg == "RS256" else ed_key
        ours = cyjwt.encode(PAYLOAD, _private_pem(key), algorithm=alg)
        assert jwt.decode(ours, _public_pem(key), algorithms=[alg]) == PAYLOAD
        theirs = jwt.encode(PAYLOAD, _private_pem(key), algorithm=alg)
        assert cyjwt.decode(theirs, _public_pem(key), algorithms=[alg]) == PAYLOAD


class TestRandomizedSignatures:
    """ECDSA and RSA-PSS randomness means tokens differ; both must verify."""

    @pytest.mark.parametrize("alg", ["ES256", "PS256"])
    def test_mutual_decode(self, alg: str, rsa_key: object, ec_key: object) -> None:
        key = ec_key if alg == "ES256" else rsa_key
        ours = cyjwt.encode(PAYLOAD, _private_pem(key), algorithm=alg)
        assert jwt.decode(ours, _public_pem(key), algorithms=[alg]) == PAYLOAD
        theirs = jwt.encode(PAYLOAD, _private_pem(key), algorithm=alg)
        assert cyjwt.decode(theirs, _public_pem(key), algorithms=[alg]) == PAYLOAD


class TestErrorParity:
    def test_wrong_curve(self, ec_key: object) -> None:
        p384 = _private_pem(ec.generate_private_key(ec.SECP384R1()))
        with pytest.raises(Exception) as ours:
            cyjwt.encode(PAYLOAD, p384, algorithm="ES256")
        with pytest.raises(Exception) as theirs:
            jwt.encode(PAYLOAD, p384, algorithm="ES256")
        assert type(ours.value).__name__ == type(theirs.value).__name__

    def test_wrong_key_family(self, ec_key: object) -> None:
        with pytest.raises(Exception) as ours:
            cyjwt.encode(PAYLOAD, ec_key, algorithm="RS256")  # type: ignore[arg-type]
        with pytest.raises(Exception) as theirs:
            jwt.encode(PAYLOAD, ec_key, algorithm="RS256")
        assert type(ours.value).__name__ == type(theirs.value).__name__

    def test_unparsable_pem(self) -> None:
        with pytest.raises(Exception) as ours:
            cyjwt.encode(PAYLOAD, "not a key", algorithm="RS256")
        with pytest.raises(Exception) as theirs:
            jwt.encode(PAYLOAD, "not a key", algorithm="RS256")
        assert type(ours.value).__name__ == type(theirs.value).__name__

    def test_short_rsa_key_warning(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        with warnings.catch_warnings(record=True) as ours:
            warnings.simplefilter("always")
            cyjwt.encode(PAYLOAD, _private_pem(key), algorithm="RS256")
        with warnings.catch_warnings(record=True) as theirs:
            warnings.simplefilter("always")
            jwt.encode(PAYLOAD, _private_pem(key), algorithm="RS256")
        assert [type(w.message).__name__ for w in ours] == [
            type(w.message).__name__ for w in theirs
        ]

    def test_signature_from_other_key(self, rsa_key: object) -> None:
        token = jwt.encode(PAYLOAD, _private_pem(rsa_key), algorithm="RS256")
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with pytest.raises(Exception) as ours:
            cyjwt.decode(token, _public_pem(other), algorithms=["RS256"])
        with pytest.raises(Exception) as theirs:
            jwt.decode(token, _public_pem(other), algorithms=["RS256"])
        assert type(ours.value).__name__ == type(theirs.value).__name__

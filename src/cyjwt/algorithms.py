"""Signature algorithms.

HS256/HS384/HS512 and the insecure ``none`` need nothing beyond the standard
library. RS*/PS*/ES*/EdDSA are enabled when the optional ``cryptography``
dependency is installed (``pip install cyjwt[crypto]``); otherwise they are
absent from :func:`get_default_algorithms` and requesting one raises
``NotImplementedError`` with an install hint.

Custom implementations only need ``prepare_key``, ``sign`` and ``verify`` and
can be installed with ``register_algorithm("X", obj)``.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from . import _core
from .exceptions import InvalidKeyError

_crypto: Any
try:  # pragma: no cover - the fallback is exercised in a dependency-free venv
    from . import _crypto_backend as _crypto

    has_crypto = True
except ImportError:  # pragma: no cover
    _crypto = None
    has_crypto = False

# Algorithms that only work with the optional `cryptography` dependency.
requires_cryptography = {
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES256K",
    "ES384",
    "ES521",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
    "EdDSA",
}


def _require_crypto() -> Any:
    if _crypto is None:
        raise NotImplementedError(
            "The 'cryptography' package is required for asymmetric algorithms. "
            "Install it with: pip install cyjwt[crypto]"
        )
    return _crypto


def force_bytes(value: object) -> bytes:
    """Return ``value`` as bytes: str is UTF-8 encoded, bytes pass through."""
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, bytes):
        return value
    raise TypeError("Expected a string value")


class Algorithm(ABC):
    """Interface for a JWS signature algorithm."""

    def _crypto_key_types(self) -> tuple[type, ...]:
        raise ValueError(
            "This method requires the cryptography library, and should only be "
            "used by cryptography-based algorithms."
        )

    @abstractmethod
    def prepare_key(self, key: Any) -> Any:
        """Validate/normalize ``key`` into whatever ``sign``/``verify`` expect."""

    def check_key_length(self, key: Any) -> str | None:
        """Return a warning message when ``key`` is weaker than recommended."""
        return None

    def check_crypto_key_type(self, key: Any) -> None:
        """Raise ``InvalidKeyError`` when ``key`` is from another key family."""
        types = self._crypto_key_types()
        if not isinstance(key, types):
            valid_classes = ", ".join(cls.__name__ for cls in types)
            raise InvalidKeyError(
                f"Expected one of {valid_classes}, got: {key.__class__.__name__}. "
                f"Invalid Key type for {self.__class__.__name__}"
            )

    @abstractmethod
    def sign(self, msg: bytes, key: Any) -> bytes:
        """Return the signature of ``msg``."""

    @abstractmethod
    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        """Return True when ``sig`` is a valid signature of ``msg``."""


class NoneAlgorithm(Algorithm):
    """The insecure JWS ``"none"`` algorithm.

    Enabled for interoperability (PyJWT parity) but never trusted: ``verify``
    always returns False, so an unsigned token only decodes with
    ``options={"verify_signature": False}``.
    """

    def prepare_key(self, key: str | None) -> None:
        if key == "":
            key = None
        if key is not None:
            raise InvalidKeyError('When alg = "none", key value must be None.')
        return None

    def sign(self, msg: bytes, key: None) -> bytes:
        return b""

    def verify(self, msg: bytes, key: None, sig: bytes) -> bool:
        return False


class HMACAlgorithm(Algorithm):
    """HMAC-SHA256/384/512."""

    SHA256: ClassVar[Any] = hashlib.sha256
    SHA384: ClassVar[Any] = hashlib.sha384
    SHA512: ClassVar[Any] = hashlib.sha512

    def __init__(self, hash_alg: Any) -> None:
        self.hash_alg = hash_alg

    def prepare_key(self, key: Any) -> bytes:
        key_bytes = force_bytes(key)
        if len(key_bytes) == 0:
            raise InvalidKeyError("HMAC key must not be empty.")
        if _core.looks_like_asymmetric_key(key_bytes) or (
            has_crypto and _require_crypto().is_der_key(key_bytes)
        ):
            raise InvalidKeyError(
                "The specified key is an asymmetric key or x509 certificate and"
                " should not be used as an HMAC secret."
            )
        if _core.looks_like_jwk(key_bytes):
            raise InvalidKeyError(
                "The specified key looks like a JWK and should not be "
                "used directly as an HMAC secret."
            )
        return key_bytes

    def check_key_length(self, key: bytes) -> str | None:
        digest = self.hash_alg()
        if len(key) < digest.digest_size:
            return (
                f"The HMAC key is {len(key)} bytes long, which is below "
                f"the minimum recommended length of {digest.digest_size} bytes for "
                f"{digest.name.upper()}. "
                f"See RFC 7518 Section 3.2."
            )
        return None

    def sign(self, msg: bytes, key: bytes) -> bytes:
        return _core.hmac_sign(msg, key, self.hash_alg)

    def verify(self, msg: bytes, key: bytes, sig: bytes) -> bool:
        return _core.hmac_verify(msg, key, sig, self.hash_alg)


# ---------------------------------------------------------------------------
# Asymmetric algorithms (require `cryptography`)
# ---------------------------------------------------------------------------


class RSAAlgorithm(Algorithm):
    """RSASSA-PKCS1-v1_5 with SHA-256/384/512 (RS*)."""

    SHA256: ClassVar[Any] = "sha256"
    SHA384: ClassVar[Any] = "sha384"
    SHA512: ClassVar[Any] = "sha512"

    _MIN_KEY_SIZE: ClassVar[int] = 2048

    def __init__(self, hash_alg: Any) -> None:
        self.hash_alg = hash_alg

    def _digest(self) -> Any:
        crypto = _require_crypto()
        # Accepts either our string constants or a cryptography hash class
        # (PyJWT exposes the latter as RSAAlgorithm.SHA256).
        if isinstance(self.hash_alg, str):
            return getattr(crypto.hashes, self.hash_alg.upper())()
        return self.hash_alg()

    def _crypto_key_types(self) -> tuple[type, ...]:
        return tuple(_require_crypto().rsa_key_types())

    def check_key_length(self, key: Any) -> str | None:
        if key.key_size < self._MIN_KEY_SIZE:
            return (
                f"The RSA key is {key.key_size} bits long, which is below "
                f"the minimum recommended size of {self._MIN_KEY_SIZE} bits. "
                f"See NIST SP 800-131A."
            )
        return None

    def prepare_key(self, key: Any) -> Any:
        crypto = _require_crypto()
        if isinstance(key, self._crypto_key_types()):
            return key

        if not isinstance(key, (bytes, str)):
            raise TypeError("Expecting a PEM-formatted key.")

        key_bytes = force_bytes(key)
        try:
            if key_bytes.startswith(b"ssh-rsa"):
                public_key = crypto.load_ssh_public_key(key_bytes)
                self.check_crypto_key_type(public_key)
                return public_key
            private_key = crypto.load_pem_private_key(key_bytes, password=None)
            self.check_crypto_key_type(private_key)
            return private_key
        except ValueError:
            try:
                public_key = crypto.load_pem_public_key(key_bytes)
                self.check_crypto_key_type(public_key)
                return public_key
            except (ValueError, crypto.UnsupportedAlgorithm):
                raise InvalidKeyError("Could not parse the provided public key.") from None

    def sign(self, msg: bytes, key: Any) -> bytes:
        crypto = _require_crypto()
        signature: bytes = key.sign(msg, crypto.padding.PKCS1v15(), self._digest())
        return signature

    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        crypto = _require_crypto()
        if isinstance(key, crypto.RSAPrivateKey):
            key = key.public_key()
        try:
            key.verify(sig, msg, crypto.padding.PKCS1v15(), self._digest())
            return True
        except crypto.InvalidSignature:
            return False


class ECAlgorithm(Algorithm):
    """ECDSA with SHA-256/384/512 (ES*), with an optional expected curve.

    JWS carries ECDSA signatures as fixed-width ``r || s``; ``cryptography``
    speaks DER, so the conversion happens on both ends.
    """

    SHA256: ClassVar[Any] = "sha256"
    SHA384: ClassVar[Any] = "sha384"
    SHA512: ClassVar[Any] = "sha512"

    def __init__(self, hash_alg: Any, expected_curve: Any = None) -> None:
        self.hash_alg = hash_alg
        self.expected_curve = expected_curve

    def _digest(self) -> Any:
        crypto = _require_crypto()
        if isinstance(self.hash_alg, str):
            return getattr(crypto.hashes, self.hash_alg.upper())()
        return self.hash_alg()

    def _crypto_key_types(self) -> tuple[type, ...]:
        return tuple(_require_crypto().ec_key_types())

    def _expected_curve_class(self) -> Any:
        expected = self.expected_curve
        if expected is None or not isinstance(expected, str):
            return expected
        return _require_crypto().curve_class(expected)

    def _validate_curve(self, key: Any) -> None:
        expected = self._expected_curve_class()
        if expected is None:
            return
        if not isinstance(key.curve, expected):
            raise InvalidKeyError(
                f"The key's curve '{key.curve.name}' does not match the expected "
                f"curve '{expected.name}' for this algorithm"
            )

    def prepare_key(self, key: Any) -> Any:
        crypto = _require_crypto()
        if isinstance(key, self._crypto_key_types()):
            self._validate_curve(key)
            return key

        if not isinstance(key, (bytes, str)):
            raise TypeError("Expecting a PEM-formatted key.")

        key_bytes = force_bytes(key)
        # The key may be a signing or a verifying key; try public first, as
        # PyJWT does, and fall back to private.
        try:
            if key_bytes.startswith(b"ecdsa-sha2-"):
                public_key = crypto.load_ssh_public_key(key_bytes)
            else:
                public_key = crypto.load_pem_public_key(key_bytes)
            self.check_crypto_key_type(public_key)
            self._validate_curve(public_key)
            return public_key
        except ValueError:
            private_key = crypto.load_pem_private_key(key_bytes, password=None)
            self.check_crypto_key_type(private_key)
            self._validate_curve(private_key)
            return private_key

    def sign(self, msg: bytes, key: Any) -> bytes:
        crypto = _require_crypto()
        der_sig = key.sign(msg, crypto.ECDSA(self._digest()))
        raw_sig: bytes = crypto.der_to_raw_signature(der_sig, key.curve.key_size)
        return raw_sig

    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        crypto = _require_crypto()
        try:
            der_sig = crypto.raw_to_der_signature(sig, key.curve.key_size)
        except ValueError:
            return False
        try:
            public_key = (
                key.public_key() if isinstance(key, crypto.EllipticCurvePrivateKey) else key
            )
            public_key.verify(der_sig, msg, crypto.ECDSA(self._digest()))
            return True
        except crypto.InvalidSignature:
            return False


class RSAPSSAlgorithm(RSAAlgorithm):
    """RSASSA-PSS with MGF1 and salt length equal to the digest size (PS*)."""

    def sign(self, msg: bytes, key: Any) -> bytes:
        crypto = _require_crypto()
        digest = self._digest()
        signature: bytes = key.sign(
            msg,
            crypto.padding.PSS(
                mgf=crypto.padding.MGF1(digest),
                salt_length=digest.digest_size,
            ),
            digest,
        )
        return signature

    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        crypto = _require_crypto()
        if isinstance(key, crypto.RSAPrivateKey):
            key = key.public_key()
        digest = self._digest()
        try:
            key.verify(
                sig,
                msg,
                crypto.padding.PSS(
                    mgf=crypto.padding.MGF1(digest),
                    salt_length=digest.digest_size,
                ),
                digest,
            )
            return True
        except crypto.InvalidSignature:
            return False


class OKPAlgorithm(Algorithm):
    """EdDSA over Ed25519 and Ed448."""

    def __init__(self, **kwargs: Any) -> None:
        pass

    def _crypto_key_types(self) -> tuple[type, ...]:
        return tuple(_require_crypto().okp_key_types())

    def prepare_key(self, key: Any) -> Any:
        crypto = _require_crypto()
        if not isinstance(key, (str, bytes)):
            self.check_crypto_key_type(key)
            return key

        key_str = key.decode("utf-8") if isinstance(key, bytes) else key
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key

        if "-----BEGIN PUBLIC" in key_str:
            loaded_key = crypto.load_pem_public_key(key_bytes)
        elif "-----BEGIN PRIVATE" in key_str:
            loaded_key = crypto.load_pem_private_key(key_bytes, password=None)
        elif key_str[0:4] == "ssh-":
            loaded_key = crypto.load_ssh_public_key(key_bytes)
        else:
            raise InvalidKeyError("Not a public or private key")

        self.check_crypto_key_type(loaded_key)
        return loaded_key

    def sign(self, msg: bytes, key: Any) -> bytes:
        msg_bytes = msg.encode("utf-8") if isinstance(msg, str) else msg
        signature: bytes = key.sign(msg_bytes)
        return signature

    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        crypto = _require_crypto()
        try:
            msg_bytes = msg.encode("utf-8") if isinstance(msg, str) else msg
            sig_bytes = sig.encode("utf-8") if isinstance(sig, str) else sig
            public_key = (
                key.public_key()
                if isinstance(key, (crypto.Ed25519PrivateKey, crypto.Ed448PrivateKey))
                else key
            )
            public_key.verify(sig_bytes, msg_bytes)
            return True
        except crypto.InvalidSignature:
            return False


def get_default_algorithms() -> dict[str, Algorithm]:
    """Return the algorithms available in this installation."""
    default_algorithms: dict[str, Algorithm] = {
        "none": NoneAlgorithm(),
        "HS256": HMACAlgorithm(HMACAlgorithm.SHA256),
        "HS384": HMACAlgorithm(HMACAlgorithm.SHA384),
        "HS512": HMACAlgorithm(HMACAlgorithm.SHA512),
    }

    if has_crypto:
        default_algorithms.update(
            {
                "RS256": RSAAlgorithm(RSAAlgorithm.SHA256),
                "RS384": RSAAlgorithm(RSAAlgorithm.SHA384),
                "RS512": RSAAlgorithm(RSAAlgorithm.SHA512),
                "ES256": ECAlgorithm(ECAlgorithm.SHA256, "secp256r1"),
                "ES256K": ECAlgorithm(ECAlgorithm.SHA256, "secp256k1"),
                "ES384": ECAlgorithm(ECAlgorithm.SHA384, "secp384r1"),
                "ES521": ECAlgorithm(ECAlgorithm.SHA512, "secp521r1"),
                # Backward-compatible alias for the long-standing PyJWT name.
                "ES512": ECAlgorithm(ECAlgorithm.SHA512, "secp521r1"),
                "PS256": RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256),
                "PS384": RSAPSSAlgorithm(RSAPSSAlgorithm.SHA384),
                "PS512": RSAPSSAlgorithm(RSAPSSAlgorithm.SHA512),
                "EdDSA": OKPAlgorithm(),
            }
        )

    return default_algorithms

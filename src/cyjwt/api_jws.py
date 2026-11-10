"""JWS (signed token) layer, API-compatible with ``jwt.api_jws.PyJWS`` 2.15."""

from __future__ import annotations

import json
import warnings
from collections.abc import Sequence
from typing import Any, ClassVar

from . import _core
from .algorithms import (
    Algorithm,
    get_default_algorithms,
    has_crypto,
    requires_cryptography,
)
from .exceptions import (
    DecodeError,
    InvalidAlgorithmError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
)
from .warnings import InsecureKeyLengthWarning, RemovedInPyjwt3Warning

Headers = dict[str, Any]

# Distinguishes "argument not passed" (default HS256) from an explicit
# algorithm=None, which means the unsigned "none" algorithm.
_ALGORITHM_UNSET = object()


class PyJWS:
    """Encode and decode compact JWS tokens (header.payload.signature)."""

    header_typ = "JWT"
    # Extensions this implementation actually understands (RFC 7797).
    _supported_crit: ClassVar[set[str]] = {"b64"}

    def __init__(
        self,
        algorithms: Sequence[str] | None = None,
        options: dict[str, Any] | None = None,
    ) -> None:
        self._algorithms = get_default_algorithms()
        self._valid_algs = set(algorithms) if algorithms is not None else set(self._algorithms)
        for key in list(self._algorithms):
            if key not in self._valid_algs:
                del self._algorithms[key]

        self.options: dict[str, Any] = self._get_default_options()
        if options is not None:
            self.options = {**self.options, **options}

    @staticmethod
    def _get_default_options() -> dict[str, Any]:
        return {"verify_signature": True, "enforce_minimum_key_length": False}

    def register_algorithm(self, alg_id: str, alg_obj: Algorithm) -> None:
        """Register a custom ``Algorithm`` under ``alg_id``."""
        if alg_id in self._algorithms:
            raise ValueError("Algorithm already has a handler.")
        if not isinstance(alg_obj, Algorithm):
            raise TypeError("Object is not of type `Algorithm`")
        self._algorithms[alg_id] = alg_obj
        self._valid_algs.add(alg_id)

    def unregister_algorithm(self, alg_id: str) -> None:
        """Remove a previously registered algorithm."""
        if alg_id not in self._algorithms:
            raise KeyError(
                "The specified algorithm could not be removed because it is not registered."
            )
        del self._algorithms[alg_id]
        self._valid_algs.remove(alg_id)

    def get_algorithms(self) -> list[str]:
        """Return the supported ``alg`` values."""
        return list(self._valid_algs)

    def get_algorithm_by_name(self, alg_name: str) -> Algorithm:
        """Return the ``Algorithm`` registered for ``alg_name``."""
        try:
            return self._algorithms[alg_name]
        except KeyError as err:
            if not has_crypto and alg_name in requires_cryptography:
                raise NotImplementedError(
                    f"Algorithm '{alg_name}' could not be found. "
                    "Do you have cryptography installed? "
                    "Install it with: pip install cyjwt[crypto]"
                ) from err
            raise NotImplementedError("Algorithm not supported") from err

    def encode(
        self,
        payload: bytes,
        key: str | bytes,
        algorithm: str | None = _ALGORITHM_UNSET,  # type: ignore[assignment]
        headers: Headers | None = None,
        json_encoder: type[json.JSONEncoder] | None = None,
        is_payload_detached: bool = False,
        sort_headers: bool = True,
    ) -> str:
        """Encode ``payload`` (already JSON bytes) into a compact JWS string."""
        if algorithm is _ALGORITHM_UNSET:
            algorithm_ = "HS256"
        elif algorithm is None:
            algorithm_ = "none"
        else:
            algorithm_ = algorithm

        # Header values win over the explicit arguments (PyJWT semantics).
        if headers:
            headers_alg = headers.get("alg")
            if headers_alg:
                algorithm_ = headers["alg"]
            if headers.get("b64") is False:
                is_payload_detached = True

        header: Headers = {"typ": self.header_typ, "alg": algorithm_}
        if headers:
            self._validate_headers(headers, encoding=True)
            header.update(headers)

        if not header["typ"]:
            del header["typ"]

        if is_payload_detached:
            header["b64"] = False
            # RFC 7797 §3: "b64" in the protected header MUST be listed in "crit".
            existing_crit = header.get("crit", [])
            if not isinstance(existing_crit, list):
                raise InvalidTokenError("Invalid 'crit' header: must be a list")
            if "b64" not in existing_crit:
                header["crit"] = [*existing_crit, "b64"]
        elif "b64" in header:
            del header["b64"]

        json_header = json.dumps(
            header, separators=(",", ":"), cls=json_encoder, sort_keys=sort_headers
        ).encode("utf-8")

        header_segment = _core.b64url_encode(json_header)
        payload_segment = payload if is_payload_detached else _core.b64url_encode(payload)

        signing_input = header_segment + b"." + payload_segment

        alg_obj = self.get_algorithm_by_name(algorithm_)
        prepared_key = alg_obj.prepare_key(key)

        key_length_msg = alg_obj.check_key_length(prepared_key)
        if key_length_msg:
            if self.options.get("enforce_minimum_key_length", False):
                raise InvalidKeyError(key_length_msg)
            warnings.warn(key_length_msg, InsecureKeyLengthWarning, stacklevel=2)

        signature = alg_obj.sign(signing_input, prepared_key)

        if is_payload_detached:
            payload_segment = b""

        return (
            header_segment + b"." + payload_segment + b"." + _core.b64url_encode(signature)
        ).decode("utf-8")

    def decode_complete(
        self,
        jwt: str | bytes,
        key: str | bytes = "",
        algorithms: Sequence[str] | None = None,
        options: dict[str, Any] | None = None,
        detached_payload: bytes | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Decode a JWS and return ``payload``, ``header`` and ``signature``."""
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode_complete() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
                stacklevel=2,
            )
        merged_options = self.options if options is None else {**self.options, **options}
        verify_signature = merged_options["verify_signature"]

        if verify_signature and not algorithms:
            raise DecodeError(
                'It is required that you pass in a value for the "algorithms"'
                " argument when calling decode()."
            )

        payload, signing_input, header, signature = self._load(jwt)

        self._validate_headers(header)

        if detached_payload is not None and header.get("b64", True) is not False:
            raise DecodeError(
                'It is only valid to pass "detached_payload" when the protected'
                ' header has "b64" set to false.'
            )

        if header.get("b64", True) is False:
            # RFC 7797 §3: a token that sets b64=false must declare it critical.
            crit = header.get("crit") or []
            if not isinstance(crit, list) or "b64" not in crit:
                raise InvalidTokenError(
                    "The 'b64' header parameter requires 'b64' to be listed in 'crit'."
                )
            if detached_payload is None:
                raise DecodeError(
                    'It is required that you pass in a value for the "detached_payload"'
                    " argument to decode a message having the b64 header set to false."
                )
            payload = detached_payload
            signing_input = b".".join([signing_input.rsplit(b".", 1)[0], payload])

        if verify_signature:
            self._verify_signature(
                signing_input,
                header,
                signature,
                key,
                algorithms,
                options=merged_options,
            )

        return {"payload": payload, "header": header, "signature": signature}

    def decode(
        self,
        jwt: str | bytes,
        key: str | bytes = "",
        algorithms: Sequence[str] | None = None,
        options: dict[str, Any] | None = None,
        detached_payload: bytes | None = None,
        **kwargs: Any,
    ) -> Any:
        """Decode a JWS and return the raw payload bytes."""
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
                stacklevel=2,
            )
        decoded = self.decode_complete(
            jwt, key, algorithms, options, detached_payload=detached_payload
        )
        return decoded["payload"]

    def get_unverified_header(self, jwt: str | bytes) -> Headers:
        """Return the header without checking the signature.

        The result must not be trusted until the signature is verified.
        """
        headers = self._load(jwt)[2]
        self._validate_headers(headers)
        return headers

    @staticmethod
    def _decode_segment(segment: bytes, name: str) -> bytes:
        """Strictly decode one base64url segment (RFC 7515 §2)."""
        try:
            return _core.b64url_decode(segment)
        except ValueError as err:
            raise DecodeError(f"Invalid {name} padding") from err

    def _load(self, jwt: str | bytes) -> tuple[bytes, bytes, Headers, bytes]:
        if isinstance(jwt, str):
            jwt = jwt.encode("utf-8")
        if not isinstance(jwt, bytes):
            raise DecodeError(f"Invalid token type. Token must be a {bytes}")

        try:
            header_segment, payload_segment, crypto_segment, signing_input = _core.split_jws(jwt)
        except ValueError as err:
            raise DecodeError("Not enough segments") from err

        header_data = self._decode_segment(header_segment, "header")

        try:
            header = json.loads(header_data)
        except (ValueError, RecursionError) as err:
            raise DecodeError(f"Invalid header string: {err}") from err
        if not isinstance(header, dict):
            raise DecodeError("Invalid header string: must be a json object")

        if header.get("b64", True) is False:
            # Detached form: the compact payload segment must be empty, so an
            # attacker cannot make us decode an unused, unauthenticated blob.
            if payload_segment:
                raise DecodeError("Payload segment must be empty when 'b64' is false.")
            payload = b""
        else:
            payload = self._decode_segment(payload_segment, "payload")

        signature = self._decode_segment(crypto_segment, "crypto")

        return payload, signing_input, header, signature

    def _verify_signature(
        self,
        signing_input: bytes,
        header: Headers,
        signature: bytes,
        key: str | bytes = "",
        algorithms: Sequence[str] | None = None,
        options: dict[str, Any] | None = None,
    ) -> None:
        effective_options = self.options if options is None else options

        try:
            alg = header["alg"]
        except KeyError:
            raise InvalidAlgorithmError("Algorithm not specified") from None

        if not alg or (algorithms is not None and alg not in algorithms):
            raise InvalidAlgorithmError("The specified alg value is not allowed")

        try:
            alg_obj = self.get_algorithm_by_name(alg)
        except NotImplementedError as err:
            raise InvalidAlgorithmError("Algorithm not supported") from err

        prepared_key = alg_obj.prepare_key(key)

        key_length_msg = alg_obj.check_key_length(prepared_key)
        if key_length_msg:
            if effective_options.get("enforce_minimum_key_length", False):
                raise InvalidKeyError(key_length_msg)
            warnings.warn(key_length_msg, InsecureKeyLengthWarning, stacklevel=4)

        if not alg_obj.verify(signing_input, prepared_key, signature):
            raise InvalidSignatureError("Signature verification failed")

    def _validate_headers(self, headers: Headers, *, encoding: bool = False) -> None:
        if "kid" in headers:
            self._validate_kid(headers["kid"])
        if not encoding and "crit" in headers:
            self._validate_crit(headers)

    def _validate_kid(self, kid: Any) -> None:
        if not isinstance(kid, str):
            raise InvalidTokenError("Key ID header parameter must be a string")

    def _validate_crit(self, headers: Headers) -> None:
        crit = headers["crit"]
        if not isinstance(crit, list) or len(crit) == 0:
            raise InvalidTokenError("Invalid 'crit' header: must be a non-empty list")
        for ext in crit:
            if not isinstance(ext, str):
                raise InvalidTokenError("Invalid 'crit' header: values must be strings")
            if ext not in self._supported_crit:
                raise InvalidTokenError(f"Unsupported critical extension: {ext}")
            if ext not in headers:
                raise InvalidTokenError(f"Critical extension '{ext}' is missing from headers")


_jws_global_obj = PyJWS()
encode = _jws_global_obj.encode
decode_complete = _jws_global_obj.decode_complete
decode = _jws_global_obj.decode
register_algorithm = _jws_global_obj.register_algorithm
unregister_algorithm = _jws_global_obj.unregister_algorithm
get_algorithm_by_name = _jws_global_obj.get_algorithm_by_name
get_unverified_header = _jws_global_obj.get_unverified_header

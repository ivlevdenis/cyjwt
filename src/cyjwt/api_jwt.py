"""JWT (claims) layer, API-compatible with ``jwt.api_jwt.PyJWT`` 2.15."""

from __future__ import annotations

import json
import time
import warnings
from calendar import timegm
from collections.abc import Container, Iterable, Sequence
from datetime import datetime, timedelta
from typing import Any, cast

from . import api_jws
from .api_jws import _ALGORITHM_UNSET, PyJWS
from .exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidJTIError,
    InvalidSubjectError,
    MissingRequiredClaimError,
)
from .warnings import RemovedInPyjwt3Warning

_TIME_CLAIMS = ("exp", "iat", "nbf")
_VERIFY_CLAIM_OPTIONS = ("exp", "nbf", "iat", "aud", "iss", "sub", "jti")
_INT_ERRORS = (ValueError, TypeError, OverflowError)


class PyJWT:
    """Encode JWT claims and validate them on decode."""

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        self.options: dict[str, Any] = self._get_default_options()
        if options is not None:
            self.options = self._merge_options(options)
        self._jws = PyJWS(options=self._get_sig_options())

    @staticmethod
    def _get_default_options() -> dict[str, Any]:
        return {
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "verify_aud": True,
            "verify_iss": True,
            "verify_sub": True,
            "verify_jti": True,
            "require": [],
            "strict_aud": False,
            "enforce_minimum_key_length": False,
        }

    def _get_sig_options(self) -> dict[str, Any]:
        return {
            "verify_signature": self.options["verify_signature"],
            "enforce_minimum_key_length": self.options.get("enforce_minimum_key_length", False),
        }

    def _merge_options(self, options: dict[str, Any] | None = None) -> dict[str, Any]:
        if options is None:
            return self.options
        merged = dict(options)
        if not merged.get("verify_signature", True):
            for claim in _VERIFY_CLAIM_OPTIONS:
                merged[f"verify_{claim}"] = merged.get(f"verify_{claim}", False)
        return {**self.options, **merged}

    def encode(
        self,
        payload: dict[str, Any],
        key: str | bytes,
        algorithm: str | None = _ALGORITHM_UNSET,  # type: ignore[assignment]
        headers: dict[str, Any] | None = None,
        json_encoder: type[json.JSONEncoder] | None = None,
        sort_headers: bool = True,
    ) -> str:
        """Encode and sign ``payload``. ``datetime`` time claims become intDate."""
        if not isinstance(payload, dict):
            raise TypeError(
                "Expecting a dict object, as JWT only supports JSON objects as payloads."
            )

        # Copy only when a time claim must be converted, so the common path
        # does not pay for a dict copy and the caller's dict is never mutated.
        if any(isinstance(payload.get(claim), datetime) for claim in _TIME_CLAIMS):
            payload = payload.copy()
            for claim in _TIME_CLAIMS:
                value = payload.get(claim)
                if isinstance(value, datetime):
                    payload[claim] = timegm(value.utctimetuple())

        if "iss" in payload and not isinstance(payload["iss"], str):
            raise TypeError("Issuer (iss) must be a string.")

        json_payload = self._encode_payload(payload, headers=headers, json_encoder=json_encoder)
        return self._jws.encode(
            json_payload,
            key,
            algorithm,
            headers,
            json_encoder,
            sort_headers=sort_headers,
        )

    def _encode_payload(
        self,
        payload: dict[str, Any],
        headers: dict[str, Any] | None = None,
        json_encoder: type[json.JSONEncoder] | None = None,
    ) -> bytes:
        """Serialize ``payload`` to JSON bytes (override to change encoding)."""
        if json_encoder is None:
            return _PAYLOAD_ENCODER.encode(payload).encode("utf-8")
        return json.dumps(payload, separators=(",", ":"), cls=json_encoder).encode("utf-8")

    def decode_complete(
        self,
        jwt: str | bytes,
        key: str | bytes = "",
        algorithms: Sequence[str] | None = None,
        options: dict[str, Any] | None = None,
        verify: bool | None = None,
        detached_payload: bytes | None = None,
        audience: str | Iterable[str] | None = None,
        issuer: str | Container[str] | None = None,
        subject: str | None = None,
        leeway: float | timedelta = 0,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Decode a JWT and return ``payload``, ``header`` and ``signature``."""
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode_complete() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
                stacklevel=2,
            )

        merged_options = self._merge_options(options)

        if verify is not None and verify != merged_options["verify_signature"]:
            warnings.warn(
                "The `verify` argument to `decode` does nothing in PyJWT 2.0 and newer. "
                "The equivalent is setting `verify_signature` to False in the "
                "`options` dictionary. "
                "This invocation has a mismatch between the kwarg and the option entry.",
                category=DeprecationWarning,
                stacklevel=2,
            )

        sig_options = {
            "verify_signature": merged_options["verify_signature"],
            "enforce_minimum_key_length": merged_options.get("enforce_minimum_key_length", False),
        }

        decoded = self._jws.decode_complete(
            jwt,
            key=key,
            algorithms=algorithms,
            options=sig_options,
            detached_payload=detached_payload,
        )

        payload = self._decode_payload(decoded)
        self._validate_claims(
            payload,
            merged_options,
            audience=audience,
            issuer=issuer,
            leeway=leeway,
            subject=subject,
        )
        decoded["payload"] = payload
        return decoded

    def _decode_payload(self, decoded: dict[str, Any]) -> dict[str, Any]:
        """Deserialize JSON payload bytes (override to change decoding)."""
        try:
            payload = json.loads(decoded["payload"])
        except (ValueError, RecursionError) as err:
            raise DecodeError(f"Invalid payload string: {err}") from err
        if not isinstance(payload, dict):
            raise DecodeError("Invalid payload string: must be a json object")
        return payload

    def decode(
        self,
        jwt: str | bytes,
        key: str | bytes = "",
        algorithms: Sequence[str] | None = None,
        options: dict[str, Any] | None = None,
        verify: bool | None = None,
        detached_payload: bytes | None = None,
        audience: str | Iterable[str] | None = None,
        subject: str | None = None,
        issuer: str | Container[str] | None = None,
        leeway: float | timedelta = 0,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Decode a JWT and return its payload dict."""
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
                stacklevel=2,
            )
        decoded = self.decode_complete(
            jwt,
            key,
            algorithms,
            options,
            verify=verify,
            detached_payload=detached_payload,
            audience=audience,
            subject=subject,
            issuer=issuer,
            leeway=leeway,
        )
        return cast(dict[str, Any], decoded["payload"])

    def _validate_claims(
        self,
        payload: dict[str, Any],
        options: dict[str, Any],
        audience: str | Iterable[str] | None = None,
        issuer: str | Container[str] | None = None,
        subject: str | None = None,
        leeway: float | timedelta = 0,
    ) -> None:
        if isinstance(leeway, timedelta):
            leeway = leeway.total_seconds()

        if audience is not None and not isinstance(audience, (str, Iterable)):
            raise TypeError("audience must be a string, iterable or None")

        self._validate_required_claims(payload, options["require"])

        now = time.time()

        if "iat" in payload and options["verify_iat"]:
            self._validate_iat(payload, now, leeway)
        if "nbf" in payload and options["verify_nbf"]:
            self._validate_nbf(payload, now, leeway)
        if "exp" in payload and options["verify_exp"]:
            self._validate_exp(payload, now, leeway)

        if options["verify_iss"]:
            self._validate_iss(payload, issuer)
        if options["verify_aud"]:
            self._validate_aud(payload, audience, strict=options.get("strict_aud", False))
        if options["verify_sub"]:
            self._validate_sub(payload, subject)
        if options["verify_jti"]:
            self._validate_jti(payload)

    def _validate_required_claims(self, payload: dict[str, Any], claims: Iterable[str]) -> None:
        for claim in claims:
            if payload.get(claim) is None:
                raise MissingRequiredClaimError(claim)

    def _validate_sub(self, payload: dict[str, Any], subject: str | None = None) -> None:
        if "sub" not in payload:
            return
        if not isinstance(payload.get("sub"), str):
            raise InvalidSubjectError("Subject must be a string")
        if subject is not None and payload.get("sub") != subject:
            raise InvalidSubjectError("Invalid subject")

    def _validate_jti(self, payload: dict[str, Any]) -> None:
        if "jti" not in payload:
            return
        if not isinstance(payload.get("jti"), str):
            raise InvalidJTIError("JWT ID must be a string")

    def _validate_iat(self, payload: dict[str, Any], now: float, leeway: float) -> None:
        try:
            iat = int(payload["iat"])
        except _INT_ERRORS:
            raise InvalidIssuedAtError("Issued At claim (iat) must be an integer.") from None
        if iat > (now + leeway):
            raise ImmatureSignatureError("The token is not yet valid (iat)")

    def _validate_nbf(self, payload: dict[str, Any], now: float, leeway: float) -> None:
        try:
            nbf = int(payload["nbf"])
        except _INT_ERRORS:
            raise DecodeError("Not Before claim (nbf) must be an integer.") from None
        if nbf > (now + leeway):
            raise ImmatureSignatureError("The token is not yet valid (nbf)")

    def _validate_exp(self, payload: dict[str, Any], now: float, leeway: float) -> None:
        try:
            exp = int(payload["exp"])
        except _INT_ERRORS:
            raise DecodeError("Expiration Time claim (exp) must be an integer.") from None
        if exp <= (now - leeway):
            raise ExpiredSignatureError("Signature has expired")

    def _validate_aud(
        self,
        payload: dict[str, Any],
        audience: str | Iterable[str] | None,
        *,
        strict: bool = False,
    ) -> None:
        if audience is None:
            if "aud" not in payload or not payload["aud"]:
                return
            raise InvalidAudienceError("Invalid audience")

        if "aud" not in payload or not payload["aud"]:
            raise MissingRequiredClaimError("aud")

        audience_claims = payload["aud"]

        if strict:
            if not isinstance(audience, str):
                raise InvalidAudienceError("Invalid audience (strict)")
            if not isinstance(audience_claims, str):
                raise InvalidAudienceError("Invalid claim format in token (strict)")
            if audience != audience_claims:
                raise InvalidAudienceError("Audience doesn't match (strict)")
            return

        if isinstance(audience_claims, str):
            audience_claims = [audience_claims]
        if not isinstance(audience_claims, list):
            raise InvalidAudienceError("Invalid claim format in token")
        if any(not isinstance(claim, str) for claim in audience_claims):
            raise InvalidAudienceError("Invalid claim format in token")

        if isinstance(audience, str):
            audience = [audience]

        if all(claim not in audience_claims for claim in audience):
            raise InvalidAudienceError("Audience doesn't match")

    def _validate_iss(self, payload: dict[str, Any], issuer: str | Container[str] | None) -> None:
        if issuer is None:
            return
        if "iss" not in payload:
            raise MissingRequiredClaimError("iss")
        iss = payload["iss"]
        if not isinstance(iss, str):
            raise InvalidIssuerError("Payload Issuer (iss) must be a string")
        if isinstance(issuer, str):
            if iss != issuer:
                raise InvalidIssuerError("Invalid issuer")
        else:
            try:
                if iss not in issuer:
                    raise InvalidIssuerError("Invalid issuer")
            except TypeError:
                raise InvalidIssuerError('Issuer param must be "str" or "Container[str]"') from None


# Cached because json.dumps() instantiates a JSONEncoder per call; the instance
# is stateless for our usage and cuts one object allocation per encode.
_PAYLOAD_ENCODER = json.JSONEncoder(separators=(",", ":"))


_jwt_global_obj = PyJWT()
# Module-level register_algorithm()/get_algorithm_by_name() operate on the JWS
# object used by the module-level encode/decode (PyJWT 2.15 does the same).
_jwt_global_obj._jws = api_jws._jws_global_obj
encode = _jwt_global_obj.encode
decode_complete = _jwt_global_obj.decode_complete
decode = _jwt_global_obj.decode

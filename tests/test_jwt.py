"""JWT claims-layer tests (exp/nbf/iat/aud/iss/sub/jti/require)."""

from __future__ import annotations

import time
import warnings
from datetime import UTC, datetime, timedelta

import pytest

from cyjwt import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidJTIError,
    InvalidSubjectError,
    MissingRequiredClaimError,
    PyJWT,
    decode,
    decode_complete,
    encode,
)

KEY = "0123456789abcdef" * 4


def _decode(token: str, **kwargs: object) -> object:
    return decode(token, KEY, algorithms=["HS256"], **kwargs)


class TestRoundTrip:
    def test_payload_roundtrip(self) -> None:
        payload = {"sub": "user", "n": 1, "flag": True, "nested": {"a": [1, 2]}}
        assert _decode(encode(payload, KEY)) == payload

    def test_datetime_claims_become_intdate(self) -> None:
        exp = datetime(2030, 1, 1, tzinfo=UTC)
        token = encode({"exp": exp}, KEY)
        decoded = _decode(token)
        assert isinstance(decoded, dict)
        assert decoded["exp"] == 1893456000

    def test_caller_dict_not_mutated(self) -> None:
        exp = datetime(2030, 1, 1, tzinfo=UTC)
        payload = {"exp": exp}
        encode(payload, KEY)
        assert payload["exp"] is exp

    def test_payload_must_be_dict(self) -> None:
        with pytest.raises(TypeError, match="Expecting a dict"):
            encode([1, 2], KEY)  # type: ignore[arg-type]

    def test_decode_complete_returns_all_parts(self) -> None:
        result = decode_complete(encode({"a": 1}, KEY), KEY, algorithms=["HS256"])
        assert set(result) == {"payload", "header", "signature"}
        assert result["payload"] == {"a": 1}
        assert isinstance(result["signature"], bytes)


class TestTimeClaims:
    def test_expired(self) -> None:
        token = encode({"exp": int(time.time()) - 10}, KEY)
        with pytest.raises(ExpiredSignatureError, match="expired"):
            _decode(token)

    def test_not_expired(self) -> None:
        assert _decode(encode({"exp": int(time.time()) + 100}, KEY))["exp"] > 0

    def test_exp_leeway(self) -> None:
        token = encode({"exp": int(time.time()) - 5}, KEY)
        assert _decode(token, leeway=60)

    def test_exp_leeway_timedelta(self) -> None:
        token = encode({"exp": int(time.time()) - 5}, KEY)
        assert _decode(token, leeway=timedelta(seconds=60))

    def test_exp_not_integer(self) -> None:
        with pytest.raises(DecodeError, match="Expiration Time"):
            _decode(encode({"exp": "soon"}, KEY))

    def test_nbf_in_future(self) -> None:
        token = encode({"nbf": int(time.time()) + 100}, KEY)
        with pytest.raises(ImmatureSignatureError, match="nbf"):
            _decode(token)

    def test_nbf_with_leeway(self) -> None:
        assert _decode(encode({"nbf": int(time.time()) + 5}, KEY), leeway=60)

    def test_nbf_not_integer(self) -> None:
        with pytest.raises(DecodeError, match="Not Before"):
            _decode(encode({"nbf": "later"}, KEY))

    def test_iat_in_future(self) -> None:
        token = encode({"iat": int(time.time()) + 100}, KEY)
        with pytest.raises(ImmatureSignatureError, match="iat"):
            _decode(token)

    def test_iat_not_integer(self) -> None:
        with pytest.raises(InvalidIssuedAtError, match="iat"):
            _decode(encode({"iat": "now"}, KEY))

    def test_verify_time_claims_disabled(self) -> None:
        token = encode({"exp": int(time.time()) - 10}, KEY)
        assert _decode(token, options={"verify_exp": False})["exp"] > 0


class TestAudience:
    def test_matching_string(self) -> None:
        token = encode({"aud": "svc"}, KEY)
        assert _decode(token, audience="svc")["aud"] == "svc"

    def test_matching_list(self) -> None:
        token = encode({"aud": ["a", "b"]}, KEY)
        assert _decode(token, audience="b")["aud"] == ["a", "b"]

    def test_mismatch(self) -> None:
        token = encode({"aud": "other"}, KEY)
        with pytest.raises(InvalidAudienceError, match="doesn't match"):
            _decode(token, audience="svc")

    def test_token_has_aud_but_no_audience_given(self) -> None:
        with pytest.raises(InvalidAudienceError):
            _decode(encode({"aud": "svc"}, KEY))

    def test_audience_given_but_claim_missing(self) -> None:
        with pytest.raises(MissingRequiredClaimError) as exc:
            _decode(encode({"a": 1}, KEY), audience="svc")
        assert exc.value.claim == "aud"

    def test_invalid_claim_format(self) -> None:
        with pytest.raises(InvalidAudienceError, match="Invalid claim format"):
            _decode(encode({"aud": 5}, KEY), audience="svc")

    def test_strict_audience(self) -> None:
        token = encode({"aud": ["a"]}, KEY)
        with pytest.raises(InvalidAudienceError, match="strict"):
            _decode(token, audience="a", options={"strict_aud": True})

    def test_strict_audience_match(self) -> None:
        token = encode({"aud": "a"}, KEY)
        assert _decode(token, audience="a", options={"strict_aud": True})["aud"] == "a"

    def test_audience_type(self) -> None:
        token = encode({"a": 1}, KEY)
        with pytest.raises(TypeError, match="audience must be"):
            _decode(token, audience=5)


class TestIssuerSubjectJti:
    def test_issuer_string(self) -> None:
        token = encode({"iss": "me"}, KEY)
        assert _decode(token, issuer="me")["iss"] == "me"

    def test_issuer_sequence(self) -> None:
        token = encode({"iss": "me"}, KEY)
        assert _decode(token, issuer=["me", "you"])["iss"] == "me"

    def test_issuer_mismatch(self) -> None:
        token = encode({"iss": "me"}, KEY)
        with pytest.raises(InvalidIssuerError):
            _decode(token, issuer="you")

    def test_issuer_missing(self) -> None:
        with pytest.raises(MissingRequiredClaimError) as exc:
            _decode(encode({"a": 1}, KEY), issuer="me")
        assert exc.value.claim == "iss"

    def test_subject_match(self) -> None:
        token = encode({"sub": "alice"}, KEY)
        assert _decode(token, subject="alice")["sub"] == "alice"

    def test_subject_mismatch(self) -> None:
        token = encode({"sub": "alice"}, KEY)
        with pytest.raises(InvalidSubjectError, match="Invalid subject"):
            _decode(token, subject="bob")

    def test_subject_not_string(self) -> None:
        with pytest.raises(InvalidSubjectError, match="must be a string"):
            _decode(encode({"sub": 1}, KEY))

    def test_jti_not_string(self) -> None:
        with pytest.raises(InvalidJTIError):
            _decode(encode({"jti": 1}, KEY))

    def test_jti_string_ok(self) -> None:
        assert _decode(encode({"jti": "id"}, KEY))["jti"] == "id"


class TestRequiredClaims:
    def test_missing_required(self) -> None:
        with pytest.raises(MissingRequiredClaimError) as exc:
            _decode(encode({"a": 1}, KEY), options={"require": ["exp"]})
        assert exc.value.claim == "exp"
        assert str(exc.value) == 'Token is missing the "exp" claim'

    def test_required_present(self) -> None:
        token = encode({"exp": int(time.time()) + 100}, KEY)
        assert _decode(token, options={"require": ["exp"]})["exp"] > 0


class TestOptions:
    def test_verify_signature_false_skips_check(self) -> None:
        token = encode({"a": 1}, KEY)
        broken = token[:-2] + "AA"
        assert decode(
            broken, "wrong", algorithms=["HS256"], options={"verify_signature": False}
        ) == {"a": 1}

    def test_verify_signature_false_without_algorithms(self) -> None:
        token = encode({"a": 1}, KEY)
        assert decode(token, "", options={"verify_signature": False}) == {"a": 1}

    def test_instance_options_are_defaults(self) -> None:
        jwt = PyJWT(options={"verify_aud": False})
        token = encode({"aud": "svc"}, KEY)
        assert jwt.decode(token, KEY, algorithms=["HS256"])["aud"] == "svc"

    def test_verify_kwarg_warns(self) -> None:
        token = encode({"a": 1}, KEY)
        with pytest.warns(DeprecationWarning):
            decode(token, KEY, algorithms=["HS256"], verify=False)

    def test_unknown_kwarg_warns(self) -> None:
        token = encode({"a": 1}, KEY)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            decode(token, KEY, algorithms=["HS256"], bogus=1)
        assert any(issubclass(w.category, DeprecationWarning) for w in caught)

"""JWS layer tests: RFC 7515 / jwt.io vectors, headers, detached payload."""

from __future__ import annotations

import hashlib
import json
import warnings

import pytest

from cyjwt import (
    DecodeError,
    InsecureKeyLengthWarning,
    InvalidAlgorithmError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
    PyJWS,
    _core,
    decode,
    encode,
    get_unverified_header,
    register_algorithm,
)
from cyjwt.algorithms import Algorithm

KEY = "0123456789abcdef" * 4
JWS = PyJWS()

# RFC 7515, Appendix A.1: key and exact segments. The RFC signs JSON that
# contains CRLF and spaces, so the token has to be reproduced verbatim instead
# of being re-serialized.
RFC_KEY = _core.b64url_decode(
    b"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
)
RFC_HEADER = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
RFC_PAYLOAD = (
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
)
RFC_SIGNATURE = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC_TOKEN = f"{RFC_HEADER}.{RFC_PAYLOAD}.{RFC_SIGNATURE}"

# Canonical jwt.io HS256 example: exact token for a known payload and secret.
JWTIO_SECRET = "your-256-bit-secret"
JWTIO_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


class TestFixedVectors:
    def test_decodes_rfc7515_token(self) -> None:
        payload = decode(RFC_TOKEN, RFC_KEY, algorithms=["HS256"], options={"verify_exp": False})
        assert payload == {
            "iss": "joe",
            "exp": 1300819380,
            "http://example.com/is_root": True,
        }

    def test_rejects_tampered_rfc_signature(self) -> None:
        tampered = RFC_TOKEN[:-3] + ("AAA" if RFC_TOKEN[-3:] != "AAA" else "BBB")
        with pytest.raises(InvalidSignatureError):
            decode(tampered, RFC_KEY, algorithms=["HS256"])

    def test_reproduces_jwtio_token(self) -> None:
        payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
        with pytest.warns(InsecureKeyLengthWarning):
            token = encode(payload, JWTIO_SECRET)
        assert token == JWTIO_TOKEN

    def test_decodes_jwtio_token(self) -> None:
        with pytest.warns(InsecureKeyLengthWarning):
            assert decode(JWTIO_TOKEN, JWTIO_SECRET, algorithms=["HS256"]) == {
                "sub": "1234567890",
                "name": "John Doe",
                "iat": 1516239022,
            }


class TestRoundTrip:
    @pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
    def test_algorithms(self, alg: str) -> None:
        token = encode({"sub": "x"}, KEY, algorithm=alg)
        assert decode(token, KEY, algorithms=[alg]) == {"sub": "x"}

    def test_key_as_str_and_bytes(self) -> None:
        token = encode({"a": 1}, KEY)
        assert decode(token, KEY.encode(), algorithms=["HS256"]) == {"a": 1}

    def test_get_unverified_header(self) -> None:
        token = encode({"a": 1}, KEY)
        assert get_unverified_header(token) == {"typ": "JWT", "alg": "HS256"}

    def test_header_overrides_algorithm(self) -> None:
        token = JWS.encode(b'{"a":1}', KEY, headers={"alg": "HS512"})
        assert get_unverified_header(token)["alg"] == "HS512"
        assert JWS.decode(token, KEY, algorithms=["HS512"]) == b'{"a":1}'


class TestHeaders:
    def test_typ_can_be_removed(self) -> None:
        token = JWS.encode(b"x", KEY, headers={"typ": ""})
        assert "typ" not in get_unverified_header(token)

    def test_sort_headers_false_preserves_order(self) -> None:
        token = JWS.encode(b"x", KEY, headers={"kid": "k"}, sort_headers=False)
        header = get_unverified_header(token)
        assert list(header) == ["typ", "alg", "kid"]

    def test_non_string_kid_rejected(self) -> None:
        with pytest.raises(InvalidTokenError, match="Key ID"):
            JWS.encode(b"x", KEY, headers={"kid": 1})

    def test_b64_header_dropped_when_true(self) -> None:
        token = JWS.encode(b"x", KEY, headers={"b64": True})
        assert "b64" not in get_unverified_header(token)

    def test_json_encoder_is_used_for_headers(self) -> None:
        class SetEncoder(json.JSONEncoder):
            def default(self, o: object) -> object:
                if isinstance(o, set):
                    return sorted(o)
                return super().default(o)

        token = JWS.encode(b"x", KEY, headers={"ext": {2, 1}}, json_encoder=SetEncoder)
        assert get_unverified_header(token)["ext"] == [1, 2]


class TestDetachedPayload:
    def test_detached_roundtrip(self) -> None:
        payload = b'{"a":1}'
        token = JWS.encode(payload, KEY, headers={"b64": False})
        header = get_unverified_header(token)
        assert header["b64"] is False
        assert header["crit"] == ["b64"]
        assert token.split(".")[1] == ""
        assert JWS.decode(token, KEY, algorithms=["HS256"], detached_payload=payload) == payload

    def test_detached_requires_payload(self) -> None:
        token = JWS.encode(b'{"a":1}', KEY, headers={"b64": False})
        with pytest.raises(DecodeError, match="detached_payload"):
            decode(token, KEY, algorithms=["HS256"])

    def test_is_payload_detached_flag(self) -> None:
        token = PyJWS().encode(b'{"a":1}', KEY, is_payload_detached=True)
        assert token.split(".")[1] == ""


class TestAlgorithms:
    def test_none_algorithm_registered_but_never_verifies(self) -> None:
        assert "none" in PyJWS().get_algorithms()
        token = encode({"a": 1}, "", algorithm=None)
        assert get_unverified_header(token)["alg"] == "none"
        assert token.endswith(".")
        with pytest.raises(InvalidSignatureError):
            decode(token, "", algorithms=["none"])

    def test_alg_not_allowed(self) -> None:
        token = encode({"a": 1}, KEY, algorithm="HS256")
        with pytest.raises(InvalidAlgorithmError, match="not allowed"):
            decode(token, KEY, algorithms=["HS512"])

    def test_unsupported_alg(self) -> None:
        header = _core.b64url_encode(b'{"alg":"unknown-256"}').decode()
        payload = _core.b64url_encode(b'{"a":1}').decode()
        token = f"{header}.{payload}.AAAA"
        with pytest.raises(InvalidAlgorithmError, match="not supported"):
            decode(token, KEY, algorithms=["unknown-256"])

    def test_missing_alg(self) -> None:
        header = _core.b64url_encode(b'{"typ":"JWT"}').decode()
        payload = _core.b64url_encode(b'{"a":1}').decode()
        token = f"{header}.{payload}.AAAA"
        with pytest.raises(InvalidAlgorithmError, match="not specified"):
            decode(token, KEY, algorithms=["HS256"])

    def test_custom_algorithm_roundtrip(self) -> None:
        class ReverseHMAC(Algorithm):
            def prepare_key(self, key: str | bytes) -> bytes:
                return key if isinstance(key, bytes) else key.encode()

            def sign(self, msg: bytes, key: bytes) -> bytes:
                return b"rev:" + key[::-1]

            def verify(self, msg: bytes, key: bytes, sig: bytes) -> bool:
                return sig == self.sign(msg, key)

        jws = PyJWS()
        jws.register_algorithm("REV", ReverseHMAC())
        token = jws.encode(b'{"a":1}', "key", algorithm="REV")
        assert jws.decode(token, "key", algorithms=["REV"]) == b'{"a":1}'

    def test_register_duplicate_and_wrong_type(self) -> None:
        jws = PyJWS()
        with pytest.raises(ValueError, match="already has a handler"):
            jws.register_algorithm("HS256", jws.get_algorithm_by_name("HS256"))
        with pytest.raises(TypeError, match="not of type"):
            jws.register_algorithm("X", object())  # type: ignore[arg-type]

    def test_unregister_unknown(self) -> None:
        with pytest.raises(KeyError, match="could not be removed"):
            PyJWS().unregister_algorithm("nope")

    def test_global_register_algorithm(self) -> None:
        class Noop(Algorithm):
            def prepare_key(self, key: str | bytes) -> None:
                return None

            def sign(self, msg: bytes, key: None) -> bytes:
                return b"sig"

            def verify(self, msg: bytes, key: None, sig: bytes) -> bool:
                return sig == b"sig"

        from cyjwt import get_algorithm_by_name, unregister_algorithm

        register_algorithm("NOOP", Noop())
        try:
            token = encode({"a": 1}, "k", algorithm="NOOP")
            assert decode(token, "k", algorithms=["NOOP"]) == {"a": 1}
            assert isinstance(get_algorithm_by_name("NOOP"), Noop)
        finally:
            unregister_algorithm("NOOP")


class TestErrors:
    def test_invalid_token_type(self) -> None:
        with pytest.raises(DecodeError, match="Invalid token type"):
            decode(123, KEY, algorithms=["HS256"])  # type: ignore[arg-type]

    def test_not_enough_segments(self) -> None:
        with pytest.raises(DecodeError, match="Not enough segments"):
            decode("abc", KEY, algorithms=["HS256"])

    def test_invalid_header_padding(self) -> None:
        with pytest.raises(DecodeError, match="Invalid header padding"):
            decode("a.b.c", KEY, algorithms=["HS256"])

    def test_invalid_header_json(self) -> None:
        header = _core.b64url_encode(b"not json").decode()
        token = f"{header}.e30.c2ln"
        with pytest.raises(DecodeError, match="Invalid header string"):
            decode(token, KEY, algorithms=["HS256"])

    def test_header_must_be_object(self) -> None:
        header = _core.b64url_encode(b"[]").decode()
        token = f"{header}.e30.c2ln"
        with pytest.raises(DecodeError, match="must be a json object"):
            decode(token, KEY, algorithms=["HS256"])

    def test_algorithms_required(self) -> None:
        token = encode({"a": 1}, KEY)
        with pytest.raises(DecodeError, match="algorithms"):
            decode(token, KEY)

    def test_pem_key_as_hmac_secret(self) -> None:
        with pytest.raises(InvalidKeyError, match="asymmetric key"):
            encode({"a": 1}, "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----")

    def test_key_type(self) -> None:
        with pytest.raises(TypeError, match="Expected a string value"):
            encode({"a": 1}, 123)  # type: ignore[arg-type]


class TestKeyHardening:
    def test_empty_key_rejected(self) -> None:
        with pytest.raises(InvalidKeyError, match="must not be empty"):
            encode({"a": 1}, "")

    def test_jwk_json_rejected(self) -> None:
        jwk = '{"kty":"oct","k":"c2VjcmV0"}'
        with pytest.raises(InvalidKeyError, match="looks like a JWK"):
            encode({"a": 1}, jwk)

    def test_short_key_warns(self) -> None:
        with pytest.warns(InsecureKeyLengthWarning, match="below the minimum"):
            token = encode({"a": 1}, "short")
        with pytest.warns(InsecureKeyLengthWarning):
            decode(token, "short", algorithms=["HS256"])

    def test_enforce_minimum_key_length(self) -> None:
        jws = PyJWS(options={"enforce_minimum_key_length": True})
        with pytest.raises(InvalidKeyError, match="below the minimum"):
            jws.encode(b"{}", "short")

    def test_long_key_does_not_warn(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            encode({"a": 1}, KEY)


class TestCrit:
    def _token(self, header_obj: dict[str, object], payload: bytes = b"{}") -> str:
        header = _core.b64url_encode(json.dumps(header_obj, separators=(",", ":")).encode())
        detached = header_obj.get("b64") is False
        payload_segment = payload if detached else _core.b64url_encode(payload)
        signing_input = header + b"." + payload_segment
        sig = _core.hmac_sign(signing_input, KEY.encode(), hashlib.sha256)
        return b".".join([header, payload_segment, _core.b64url_encode(sig)]).decode()

    def test_unsupported_critical_extension(self) -> None:
        token = self._token({"alg": "HS256", "crit": ["exp"]})
        with pytest.raises(InvalidTokenError, match="Unsupported critical extension"):
            decode(token, KEY, algorithms=["HS256"])

    def test_crit_must_be_non_empty_list(self) -> None:
        token = self._token({"alg": "HS256", "crit": []})
        with pytest.raises(InvalidTokenError, match="non-empty list"):
            decode(token, KEY, algorithms=["HS256"])

    def test_crit_values_must_be_strings(self) -> None:
        token = self._token({"alg": "HS256", "crit": [1]})
        with pytest.raises(InvalidTokenError, match="values must be strings"):
            decode(token, KEY, algorithms=["HS256"])

    def test_critical_extension_must_be_present(self) -> None:
        token = self._token({"alg": "HS256", "crit": ["b64"]})
        with pytest.raises(InvalidTokenError, match="missing from headers"):
            decode(token, KEY, algorithms=["HS256"])

    def test_b64_without_crit_rejected(self) -> None:
        token = self._token({"alg": "HS256", "b64": False}, payload=b"")
        with pytest.raises(InvalidTokenError, match="requires 'b64'"):
            decode(token, KEY, algorithms=["HS256"], detached_payload=b"{}")

    def test_non_empty_payload_segment_when_detached(self) -> None:
        header = _core.b64url_encode(
            json.dumps({"alg": "HS256", "b64": False, "crit": ["b64"]}).encode()
        )
        token = b".".join([header, b"e30", b"AAAA"]).decode()
        with pytest.raises(DecodeError, match="must be empty"):
            decode(token, KEY, algorithms=["HS256"], detached_payload=b"{}")

    def test_detached_payload_on_regular_token(self) -> None:
        token = encode({"a": 1}, KEY)
        with pytest.raises(DecodeError, match="only valid to pass"):
            decode(token, KEY, algorithms=["HS256"], detached_payload=b"{}")

"""Differential tests against the real PyJWT (skipped when it is not installed).

These prove drop-in compatibility for the HS* subset instead of asserting
hand-written expectations only.
"""

from __future__ import annotations

import time

import pytest

jwt = pytest.importorskip("jwt")

import cyjwt  # noqa: E402

KEY = "0123456789abcdef" * 4
EXPIRED = {"sub": "a", "exp": 1}
FUTURE = {"sub": "a", "nbf": int(time.time()) + 10_000}


def _type_name(exc_info: pytest.ExceptionInfo[BaseException]) -> str:
    return type(exc_info.value).__name__


class TestEncodeParity:
    @pytest.mark.parametrize(
        "payload",
        [
            {"a": 1},
            {"sub": "x", "aud": "svc", "iss": "me"},
            {"nested": [1, {"b": None}], "f": 1.5, "t": True},
            {"unicode": "привет", "emoji": "🔐"},
            {},
        ],
    )
    def test_encode_identical(self, payload: dict[str, object]) -> None:
        assert cyjwt.encode(payload, KEY) == jwt.encode(payload, KEY)

    @pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
    def test_all_hmac_algorithms(self, alg: str) -> None:
        assert cyjwt.encode({"a": 1}, KEY, algorithm=alg) == jwt.encode(
            {"a": 1}, KEY, algorithm=alg
        )

    def test_headers_and_sorting(self) -> None:
        headers = {"kid": "key-1", "cty": "JWT"}
        assert cyjwt.encode({"a": 1}, KEY, headers=headers) == jwt.encode(
            {"a": 1}, KEY, headers=headers
        )
        assert cyjwt.encode({"a": 1}, KEY, headers=headers, sort_headers=False) == jwt.encode(
            {"a": 1}, KEY, headers=headers, sort_headers=False
        )

    def test_bytes_key(self) -> None:
        assert cyjwt.encode({"a": 1}, b"raw-bytes-0123456789abcdef01234567") == jwt.encode(
            {"a": 1}, b"raw-bytes-0123456789abcdef01234567"
        )


class TestDecodeParity:
    def test_decodes_pyjwt_tokens(self) -> None:
        token = jwt.encode({"sub": "x", "aud": "svc"}, KEY)
        assert cyjwt.decode(token, KEY, algorithms=["HS256"], audience="svc") == (
            jwt.decode(token, KEY, algorithms=["HS256"], audience="svc")
        )

    def test_pyjwt_decodes_our_tokens(self) -> None:
        token = cyjwt.encode({"sub": "x"}, KEY)
        assert jwt.decode(token, KEY, algorithms=["HS256"]) == {"sub": "x"}

    def test_detached_payload_identical(self) -> None:
        payload = {"a": 1}
        raw = b'{"a":1}'
        ours = cyjwt.encode(payload, KEY, headers={"b64": False})
        theirs = jwt.encode(payload, KEY, headers={"b64": False})
        assert ours == theirs
        assert cyjwt.decode(ours, KEY, algorithms=["HS256"], detached_payload=raw) == jwt.decode(
            theirs, KEY, algorithms=["HS256"], detached_payload=raw
        )

    def test_unverified_header(self) -> None:
        token = jwt.encode({"a": 1}, KEY, headers={"kid": "k"})
        assert cyjwt.get_unverified_header(token) == jwt.get_unverified_header(token)


class TestErrorParity:
    @pytest.mark.parametrize(
        "token_kwargs",
        [
            {"payload": EXPIRED},
            {"payload": FUTURE},
            {"payload": {"aud": "svc"}},
            {"payload": {"iss": "me"}},
            {"payload": {"sub": 1}},
            {"payload": {"jti": 1}},
            {"payload": {"exp": "soon"}},
        ],
    )
    def test_same_exception_type(self, token_kwargs: dict[str, object]) -> None:
        payload = token_kwargs["payload"]
        token = jwt.encode(payload, KEY)  # type: ignore[arg-type]
        decode_kwargs: dict[str, object] = {}
        if payload == {"aud": "svc"}:
            decode_kwargs["audience"] = "other"
        if payload == {"iss": "me"}:
            decode_kwargs["issuer"] = "other"

        with pytest.raises(Exception) as ours:
            cyjwt.decode(token, KEY, algorithms=["HS256"], **decode_kwargs)  # type: ignore[arg-type]
        with pytest.raises(Exception) as theirs:
            jwt.decode(token, KEY, algorithms=["HS256"], **decode_kwargs)

        assert _type_name(ours) == _type_name(theirs)

    def test_tampered_signature(self) -> None:
        token = jwt.encode({"a": 1}, KEY)
        broken = token[:-2] + ("AA" if token[-2:] != "AA" else "BB")
        with pytest.raises(Exception) as ours:
            cyjwt.decode(broken, KEY, algorithms=["HS256"])
        with pytest.raises(Exception) as theirs:
            jwt.decode(broken, KEY, algorithms=["HS256"])
        assert _type_name(ours) == _type_name(theirs)

    def test_wrong_algorithm(self) -> None:
        token = jwt.encode({"a": 1}, KEY, algorithm="HS256")
        with pytest.raises(Exception) as ours:
            cyjwt.decode(token, KEY, algorithms=["HS512"])
        with pytest.raises(Exception) as theirs:
            jwt.decode(token, KEY, algorithms=["HS512"])
        assert _type_name(ours) == _type_name(theirs)

    def test_missing_algorithms_argument(self) -> None:
        token = jwt.encode({"a": 1}, KEY)
        with pytest.raises(Exception) as ours:
            cyjwt.decode(token, KEY)
        with pytest.raises(Exception) as theirs:
            jwt.decode(token, KEY)
        assert _type_name(ours) == _type_name(theirs)

    def test_asymmetric_key_rejected_by_both(self) -> None:
        pem = "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----"
        with pytest.raises(Exception) as ours:
            cyjwt.encode({"a": 1}, pem)
        with pytest.raises(Exception) as theirs:
            jwt.encode({"a": 1}, pem)
        assert _type_name(ours) == _type_name(theirs)

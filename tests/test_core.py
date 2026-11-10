"""Tests for the Cython core (base64url, JWS splitting, HMAC)."""

from __future__ import annotations

import base64
import hashlib
import hmac

import pytest

from cyjwt import _core


def _ref_b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


class TestBase64UrlEncode:
    @pytest.mark.parametrize(
        "data",
        [b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar", bytes(range(256))],
    )
    def test_matches_stdlib(self, data: bytes) -> None:
        assert _core.b64url_encode(data) == _ref_b64url(data)

    def test_no_padding(self) -> None:
        assert _core.b64url_encode(b"f") == b"Zg"
        assert _core.b64url_encode(b"fo") == b"Zm8"
        assert _core.b64url_encode(b"foo") == b"Zm9v"


class TestBase64UrlDecode:
    @pytest.mark.parametrize(
        "data",
        [b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar", bytes(range(256))],
    )
    def test_roundtrip(self, data: bytes) -> None:
        assert _core.b64url_decode(_ref_b64url(data)) == data

    def test_known_values(self) -> None:
        assert _core.b64url_decode(b"Zg") == b"f"
        assert _core.b64url_decode(b"Zm8") == b"fo"
        assert _core.b64url_decode(b"Zm9v") == b"foo"

    def test_accepts_padding(self) -> None:
        assert _core.b64url_decode(b"Zg==") == b"f"
        assert _core.b64url_decode(b"Zm8=") == b"fo"
        assert _core.b64url_decode(b"Zm9v") == b"foo"

    @pytest.mark.parametrize(
        "bad",
        [
            b"a",  # length 1 mod 4
            b"ab=",  # padded length not multiple of 4
            b"ab===",  # more than two padding chars
            b"a=b=",  # padding in the middle
            b"ab!c",  # invalid character
            b"ab c",  # whitespace is not silently ignored
            b"Zh",  # non-zero trailing bits (non-canonical)
            b"Zm9",  # non-zero trailing bits (non-canonical)
            b"\xff\xfe",
        ],
    )
    def test_rejects_invalid(self, bad: bytes) -> None:
        with pytest.raises(ValueError):
            _core.b64url_decode(bad)


class TestSplitJws:
    def test_three_segments(self) -> None:
        assert _core.split_jws(b"a.b.c") == (b"a", b"b", b"c", b"a.b")

    def test_extra_dots_stay_in_payload(self) -> None:
        assert _core.split_jws(b"a.b.c.d") == (b"a", b"b.c", b"d", b"a.b.c")

    def test_empty_segments(self) -> None:
        assert _core.split_jws(b"..") == (b"", b"", b"", b".")

    @pytest.mark.parametrize("bad", [b"", b"abc", b"a.b"])
    def test_not_enough_segments(self, bad: bytes) -> None:
        with pytest.raises(ValueError, match="Not enough segments"):
            _core.split_jws(bad)


class TestHmac:
    def test_sign_matches_stdlib(self) -> None:
        msg, key = b"message", b"secret"
        assert (
            _core.hmac_sign(msg, key, hashlib.sha256) == hmac.new(key, msg, hashlib.sha256).digest()
        )

    def test_verify_ok(self) -> None:
        sig = _core.hmac_sign(b"m", b"k", hashlib.sha384)
        assert _core.hmac_verify(b"m", b"k", sig, hashlib.sha384) is True

    def test_verify_rejects_tampering(self) -> None:
        sig = _core.hmac_sign(b"m", b"k", hashlib.sha256)
        assert _core.hmac_verify(b"m2", b"k", sig, hashlib.sha256) is False
        assert _core.hmac_verify(b"m", b"k2", sig, hashlib.sha256) is False
        assert _core.hmac_verify(b"m", b"k", sig[:-1], hashlib.sha256) is False
        assert _core.hmac_verify(b"m", b"k", sig + b"\x00", hashlib.sha256) is False


class TestAsymmetricKeyDetection:
    @pytest.mark.parametrize(
        "key",
        [
            b"-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----",
            b"-----BEGIN RSA PRIVATE KEY-----\n...",
            b"ssh-rsa AAAAB3NzaC1yc2E...",
            b"ssh-ed25519 AAAAC3NzaC1lZDI1...",
            b"ecdsa-sha2-nistp256 AAAAE2Vj...",
        ],
    )
    def test_detects(self, key: bytes) -> None:
        assert _core.looks_like_asymmetric_key(key) is True

    @pytest.mark.parametrize("key", [b"secret", b"", b"not-a-key"])
    def test_plain_secret(self, key: bytes) -> None:
        assert _core.looks_like_asymmetric_key(key) is False

# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
#
# boundscheck/wraparound are disabled only because every write below is bounded
# by an output buffer sized from the input length; no index comes from the user.
"""Cython hot paths for cyjwt.

Everything here is byte-oriented and has no third-party dependencies:

- ``b64url_encode`` / ``b64url_decode``: unpadded base64url (RFC 7515 §2),
  single allocation, C-level loop;
- ``split_jws``: splits a compact JWS in one pass;
- ``hmac_sign`` / ``hmac_verify``: HMAC via the stdlib C implementation, with
  a constant-time comparison done in C;
- ``looks_like_asymmetric_key``: cheap guard so an RSA/EC PEM or SSH key can
  never be silently used as an HMAC secret (algorithm-confusion defence).

The Python API lives in ``api_jws.py`` / ``api_jwt.py``.
"""

from cpython.bytes cimport PyBytes_AS_STRING, PyBytes_FromStringAndSize

import hmac
import json

# ---------------------------------------------------------------------------
# base64url tables
# ---------------------------------------------------------------------------

cdef const char* _B64_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

cdef unsigned char _B64_DEC[256]


cdef void _init_tables() noexcept:
    cdef int i
    for i in range(256):
        _B64_DEC[i] = 255
    for i in range(64):
        _B64_DEC[<unsigned char>_B64_URL[i]] = <unsigned char>i


_init_tables()


cdef inline unsigned int _dec_char(unsigned char ch) noexcept nogil:
    """Return the 6-bit value of ``ch``, or 255 when it is not base64url."""
    return _B64_DEC[ch]


# ---------------------------------------------------------------------------
# Level-1 helpers (declared in _core.pxd)
# ---------------------------------------------------------------------------


cdef bint ct_equal(
    const unsigned char* a, const unsigned char* b, Py_ssize_t n
) noexcept nogil:
    """Constant-time equality for two ``n``-byte buffers."""
    cdef Py_ssize_t i
    cdef unsigned char diff = 0
    for i in range(n):
        diff |= a[i] ^ b[i]
    return diff == 0


cdef Py_ssize_t _find_dot(
    const unsigned char* src, Py_ssize_t start, Py_ssize_t n
) noexcept nogil:
    cdef Py_ssize_t i
    for i in range(start, n):
        if src[i] == 46:  # '.'
            return i
    return -1


cdef Py_ssize_t _rfind_dot(
    const unsigned char* src, Py_ssize_t stop, Py_ssize_t n
) noexcept nogil:
    cdef Py_ssize_t i = stop
    while i >= 0:
        if src[i] == 46:  # '.'
            return i
        i -= 1
    return -1


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def b64url_encode(bytes data):
    """Encode ``data`` as unpadded base64url bytes (RFC 7515 §2)."""
    cdef Py_ssize_t n = len(data)
    cdef Py_ssize_t out_n = (n * 4 + 2) // 3
    cdef bytes out = PyBytes_FromStringAndSize(NULL, out_n)
    cdef const unsigned char* src = <const unsigned char*>PyBytes_AS_STRING(data)
    cdef char* dst = PyBytes_AS_STRING(out)
    cdef Py_ssize_t i = 0
    cdef Py_ssize_t j = 0
    cdef unsigned int v

    while i + 3 <= n:
        v = (src[i] << 16) | (src[i + 1] << 8) | src[i + 2]
        dst[j] = _B64_URL[v >> 18]
        dst[j + 1] = _B64_URL[(v >> 12) & 63]
        dst[j + 2] = _B64_URL[(v >> 6) & 63]
        dst[j + 3] = _B64_URL[v & 63]
        i += 3
        j += 4

    if n - i == 1:
        v = src[i] << 16
        dst[j] = _B64_URL[v >> 18]
        dst[j + 1] = _B64_URL[(v >> 12) & 63]
    elif n - i == 2:
        v = (src[i] << 16) | (src[i + 1] << 8)
        dst[j] = _B64_URL[v >> 18]
        dst[j + 1] = _B64_URL[(v >> 12) & 63]
        dst[j + 2] = _B64_URL[(v >> 6) & 63]

    return out


def b64url_decode(bytes data):
    """Decode base64url ``data``.

    Trailing ``=`` padding is tolerated (1 or 2 characters); padding elsewhere,
    characters outside the base64url alphabet, lengths that are 1 mod 4, and
    a padded length that is not a multiple of 4 raise ``ValueError``.

    The decode is strict: unlike ``binascii``/``base64.urlsafe_b64decode`` it
    never silently drops stray characters, so a corrupted segment cannot
    decode to attacker-chosen bytes.
    """
    cdef Py_ssize_t n = len(data)
    cdef Py_ssize_t eff = n
    cdef Py_ssize_t pad = 0
    cdef const unsigned char* src = <const unsigned char*>PyBytes_AS_STRING(data)
    cdef Py_ssize_t out_n
    cdef Py_ssize_t i = 0
    cdef Py_ssize_t k = 0
    cdef Py_ssize_t rem
    cdef unsigned int a
    cdef unsigned int b
    cdef unsigned int c
    cdef unsigned int d
    cdef char* dst

    while eff > 0 and src[eff - 1] == 61:  # '='
        eff -= 1
        pad += 1

    if pad > 2:
        raise ValueError("invalid base64url padding")
    if pad and n % 4 != 0:
        raise ValueError("invalid base64url padding")

    rem = eff % 4
    if rem == 1:
        raise ValueError("invalid base64url length")

    out_n = (eff * 3) // 4
    if out_n == 0:
        return b""

    cdef bytes out = PyBytes_FromStringAndSize(NULL, out_n)
    dst = PyBytes_AS_STRING(out)

    while i + 4 <= eff:
        a = _dec_char(src[i])
        b = _dec_char(src[i + 1])
        c = _dec_char(src[i + 2])
        if a > 63 or b > 63 or c > 63:
            raise ValueError(f"invalid base64url character at index {i}")
        d = _dec_char(src[i + 3])
        if d > 63:
            raise ValueError(f"invalid base64url character at index {i + 3}")
        dst[k] = (a << 2) | (b >> 4)
        dst[k + 1] = ((b & 15) << 4) | (c >> 2)
        dst[k + 2] = ((c & 3) << 6) | d
        i += 4
        k += 3

    rem = eff - i
    if rem >= 2:
        a = _dec_char(src[i])
        b = _dec_char(src[i + 1])
        if a > 63 or b > 63:
            raise ValueError(f"invalid base64url character at index {i}")
        dst[k] = (a << 2) | (b >> 4)
        if rem == 2:
            # Last 4 bits of the 2-char group are unused and must be zero.
            if b & 15:
                raise ValueError("non-canonical base64url (non-zero trailing bits)")
        else:
            c = _dec_char(src[i + 2])
            if c > 63:
                raise ValueError(f"invalid base64url character at index {i + 2}")
            # Last 2 bits of the 3-char group are unused and must be zero.
            if c & 3:
                raise ValueError("non-canonical base64url (non-zero trailing bits)")
            dst[k + 1] = ((b & 15) << 4) | (c >> 2)

    return out


def split_jws(bytes token):
    """Split a compact JWS into ``(header, payload, signature, signing_input)``.

    Uses the first and last ``'.'`` exactly like PyJWT does, so any extra dots
    stay inside the payload segment. Raises ``ValueError("Not enough segments")``
    when there are fewer than two dots.
    """
    cdef Py_ssize_t n = len(token)
    cdef const unsigned char* src = <const unsigned char*>PyBytes_AS_STRING(token)
    cdef Py_ssize_t first = _find_dot(src, 0, n)
    cdef Py_ssize_t last = _rfind_dot(src, n - 1, n)

    if first < 0 or last < 0 or first == last:
        raise ValueError("Not enough segments")

    return (
        token[:first],
        token[first + 1 : last],
        token[last + 1 :],
        token[:last],
    )


def hmac_sign(bytes msg, bytes key, object digestmod):
    """Return ``HMAC(key, msg)`` using the stdlib C implementation."""
    return hmac.new(key, msg, digestmod).digest()


def hmac_verify(bytes msg, bytes key, bytes sig, object digestmod):
    """Verify ``HMAC(key, msg)`` against ``sig`` in constant time."""
    cdef bytes expected = hmac.new(key, msg, digestmod).digest()
    cdef Py_ssize_t n = len(expected)

    if len(sig) != n:
        return False
    if n == 0:
        return True
    return ct_equal(
        <const unsigned char*>PyBytes_AS_STRING(expected),
        <const unsigned char*>PyBytes_AS_STRING(sig),
        n,
    )


cdef tuple _ASYMMETRIC_PREFIXES = (
    b"ssh-ed25519",
    b"ssh-rsa",
    b"ssh-dss",
    b"ecdsa-sha2-nistp256",
    b"ecdsa-sha2-nistp384",
    b"ecdsa-sha2-nistp521",
)


def looks_like_jwk(bytes key):
    """Return True if ``key`` is JSON containing a ``kty`` member.

    Raw JWK JSON is not secret material, so it must not be used as an HMAC key;
    the caller has to extract ``"k"`` first (PyJWT 2.15 parity).
    """
    cdef object obj
    cdef list stack
    cdef object current

    stripped = key.lstrip()
    if not stripped.startswith((b"{", b"[")):
        return False

    try:
        obj = json.loads(key)
    except ValueError:
        return False

    stack = [obj]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            if "kty" in current:
                return True
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return False


def looks_like_asymmetric_key(bytes key):
    """Return True if ``key`` looks like a PEM/SSH/asymmetric key.

    Used to refuse asymmetric keys as HMAC secrets (algorithm-confusion
    defence). Detection is deliberately broad on the PEM side: any
    ``-----BEGIN ...-----`` marker counts.
    """
    cdef object prefix
    for prefix in _ASYMMETRIC_PREFIXES:
        if key.startswith(prefix):
            return True
    return key.find(b"-----BEGIN ") >= 0

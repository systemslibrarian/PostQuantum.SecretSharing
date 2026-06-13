"""
Independent reference implementation of PostQuantum.SecretSharing's primitives.

This file is deliberately *not* production code. It exists only to generate and
cross-check test vectors against the C# implementation. It uses simple, readable
constructions (table-based GF math) precisely because it must be obviously
correct rather than constant-time or fast. If the C# (constant-time, table-free)
implementation and this (table-based) reference agree on every vector, both are
very likely correct.

Field: GF(2^8) with the AES reduction polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
Check value: HKDF-SHA256(ikm=secret, salt=splitId, info="PQSS-v1-check", L=32).
"""

import hashlib
import hmac

REDUCTION_POLY = 0x11B


# --- GF(2^8) arithmetic (table-based; reference only) ------------------------

def _build_tables():
    """Build log/antilog tables using generator 0x03. Reference convenience only."""
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        # multiply x by the generator 0x03 = (x+1)
        x = _mul_notable(x, 0x03)
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    return exp, log


def _mul_notable(a, b):
    """Russian-peasant multiply, used only to bootstrap the tables."""
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= (REDUCTION_POLY & 0xFF)
        b >>= 1
    return r


_EXP, _LOG = _build_tables()


def gf_add(a, b):
    return a ^ b


def gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def gf_inv(a):
    if a == 0:
        raise ValueError("0 has no inverse in GF(2^8)")
    return _EXP[255 - _LOG[a]]


def gf_div(a, b):
    return gf_mul(a, gf_inv(b))


def gf_pow(a, e):
    r = 1
    for _ in range(e):
        r = gf_mul(r, a)
    return r


# --- Shamir split / reconstruct ---------------------------------------------

def split_with_coeffs(secret, k, n, coeff_rows):
    """
    Split `secret` (bytes) into n shares with threshold k, using the supplied
    deterministic coefficient rows.

    coeff_rows is a list of (k-1) rows, each `len(secret)` bytes long. Row r
    holds the coefficient of x^(r+1) for every secret byte. This determinism is
    what makes the emitted vectors reproducible.

    Returns a list of (x, y_bytes) tuples for x in 1..n.
    """
    assert 2 <= k <= n <= 255
    assert len(coeff_rows) == k - 1
    for row in coeff_rows:
        assert len(row) == len(secret)

    shares = []
    for x in range(1, n + 1):
        y = bytearray(len(secret))
        for j in range(len(secret)):
            # Horner evaluation of s + c1*x + c2*x^2 + ... at point x.
            acc = 0
            for r in range(k - 1, 0, -1):
                acc = gf_add(gf_mul(acc, x), coeff_rows[r - 1][j])
            acc = gf_add(gf_mul(acc, x), secret[j])
            y[j] = acc
        shares.append((x, bytes(y)))
    return shares


def reconstruct(shares):
    """Lagrange-interpolate at x=0 from a list of (x, y_bytes) tuples."""
    xs = [s[0] for s in shares]
    length = len(shares[0][1])
    # Lagrange basis coefficients at x=0: L_i = prod_{m!=i} x_m / (x_m XOR x_i).
    basis = []
    for i, xi in enumerate(xs):
        num = 1
        den = 1
        for m, xm in enumerate(xs):
            if m == i:
                continue
            num = gf_mul(num, xm)
            den = gf_mul(den, gf_add(xm, xi))
        basis.append(gf_div(num, den))

    out = bytearray(length)
    for j in range(length):
        acc = 0
        for i in range(len(shares)):
            acc = gf_add(acc, gf_mul(shares[i][1][j], basis[i]))
        out[j] = acc
    return bytes(out)


# --- HKDF-SHA256 check value -------------------------------------------------

def _hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk, info, length):
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def check_value(secret, split_id):
    """HKDF-SHA256(ikm=secret, salt=split_id, info='PQSS-v1-check', L=32)."""
    prk = _hkdf_extract(split_id, secret)
    return _hkdf_expand(prk, b"PQSS-v1-check", 32)

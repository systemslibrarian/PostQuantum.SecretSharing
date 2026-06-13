"""
Emit docs/test-vectors.json from the independent reference implementation.

Determinism: every vector uses fixed, listed coefficients and fixed secrets/
splitIds. Re-running this script must produce byte-identical output; CI runs it
and `git diff --exit-code`s the result to guard against drift between the
reference and the committed vectors.

Usage:  python reference/generate_vectors.py
"""

import hashlib
import json
import os

import shamir_reference as ref


def _fixed_bytes(seed, length):
    """Deterministic pseudo-random-looking bytes from a SHA-256 stream.

    Not cryptographic — purely to produce stable, arbitrary test data without
    embedding huge literals. Independent of any RNG.
    """
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        counter += 1
    return bytes(out[:length])


def gf_mul_table_digest():
    """SHA-256 over the full 256x256 GF multiplication table (row-major)."""
    table = bytearray(256 * 256)
    for a in range(256):
        for b in range(256):
            table[a * 256 + b] = ref.gf_mul(a, b)
    return hashlib.sha256(bytes(table)).hexdigest(), table


def all_inverses():
    return [ref.gf_inv(a) for a in range(1, 256)]  # 1..255


def build():
    vectors = {}

    # --- GF multiplication table digest + inverses ---
    digest, _ = gf_mul_table_digest()
    vectors["gf_mul_table_sha256"] = digest
    vectors["gf_inverses_1_to_255"] = all_inverses()

    # --- Split vectors (fixed coefficients) ---
    split_specs = [
        # (label, k, n, secret_len)
        ("k2n3_len1", 2, 3, 1),
        ("k3n5_len32", 3, 5, 32),
        ("k5n5_len32", 5, 5, 32),
        ("k2n255_len1", 2, 255, 1),
        ("k3n5_len4096", 3, 5, 4096),
        ("k2n3_len32", 2, 3, 32),
    ]

    split_vectors = []
    for label, k, n, slen in split_specs:
        secret = _fixed_bytes(f"secret:{label}", slen)
        coeff_rows = [_fixed_bytes(f"coeff:{label}:{r}", slen) for r in range(k - 1)]
        shares = ref.split_with_coeffs(secret, k, n, coeff_rows)
        split_vectors.append({
            "label": label,
            "k": k,
            "n": n,
            "secretLength": slen,
            "secret": secret.hex(),
            "coeffRows": [row.hex() for row in coeff_rows],
            "shares": [{"x": x, "y": y.hex()} for (x, y) in shares],
        })
    vectors["split"] = split_vectors

    # --- Reconstruct vectors (subset -> expected secret) ---
    reconstruct_vectors = []
    recon_specs = [
        ("k2n3_len1", [1, 2]),
        ("k3n5_len32", [1, 3, 5]),
        ("k5n5_len32", [1, 2, 3, 4, 5]),
        ("k3n5_len4096", [2, 4, 5]),
    ]
    by_label = {sv["label"]: sv for sv in split_vectors}
    for label, xs in recon_specs:
        sv = by_label[label]
        chosen = [(s["x"], bytes.fromhex(s["y"])) for s in sv["shares"] if s["x"] in xs]
        secret = ref.reconstruct(chosen)
        assert secret.hex() == sv["secret"], f"reference self-check failed for {label}"
        reconstruct_vectors.append({
            "label": label,
            "k": sv["k"],
            "xs": xs,
            "shares": [{"x": x, "y": y.hex()} for (x, y) in chosen],
            "expectedSecret": secret.hex(),
        })
    vectors["reconstruct"] = reconstruct_vectors

    # --- Check value vectors ---
    check_specs = [
        ("cv_32zero", bytes(32), bytes(range(16))),
        ("cv_mixed", _fixed_bytes("cv:secret", 32), _fixed_bytes("cv:salt", 16)),
    ]
    check_vectors = []
    for label, secret, split_id in check_specs:
        cv = ref.check_value(secret, split_id)
        check_vectors.append({
            "label": label,
            "secret": secret.hex(),
            "splitId": split_id.hex(),
            "checkValue": cv.hex(),
        })
    vectors["checkValue"] = check_vectors

    return vectors


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.normpath(os.path.join(here, "..", "docs", "test-vectors.json"))
    vectors = build()
    text = json.dumps(vectors, indent=2, sort_keys=True) + "\n"
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"wrote {out_path} ({len(text)} bytes)")


if __name__ == "__main__":
    main()

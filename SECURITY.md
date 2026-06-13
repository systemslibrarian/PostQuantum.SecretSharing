# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately**, not in public issues.

Use GitHub's private vulnerability reporting for this repository:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** (GitHub Security Advisories).
3. Provide a clear description, affected versions, reproduction steps, and impact.

We will acknowledge your report, work with you on a fix and a coordinated
disclosure timeline, and credit you (if you wish) in the advisory.

Please do **not** open public issues or pull requests for undisclosed
vulnerabilities.

## Scope

This policy covers the `PostQuantum.SecretSharing` package in this repository.

Before reporting, please review [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) and
[`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md): several properties (malicious dealer,
low-entropy check-value oracle, memory dumps/swap, side channels beyond cache
timing) are **documented as out of scope for v1**. Reports of already-documented
gaps are welcome as input but are not treated as vulnerabilities.

## Maturity

This package is **not independently audited**. It is carefully engineered, with
constant-time field math, a strict fail-closed parser, and honest documentation —
but "carefully engineered" and "audited" are different claims. Use it accordingly.

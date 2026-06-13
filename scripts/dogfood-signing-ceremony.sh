#!/usr/bin/env bash
#
# dogfood-signing-ceremony.sh — a reproducible, end-to-end ceremony that protects
# a code-signing private key with PostQuantum.SecretSharing (3-of-5), then PROVES
# the recovered key is byte-identical and still signs verifiably.
#
# It uses a freshly-generated EC P-384 key as a representative stand-in for a real
# code-signing / NuGet author-signing private key. To run it for YOUR real key,
# see docs/CASE-STUDY-signing-key.md ("Adapting this to your real key").
#
# Requirements: bash, openssl >= 3, the .NET SDK. Run from the repo root.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "Building the pqss CLI…"
dotnet build "$REPO/samples/PqssCli" -c Release >/dev/null
PQSS_DLL="$REPO/samples/PqssCli/bin/Release/net10.0/pqss.dll"
pqss() { dotnet "$PQSS_DLL" "$@"; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
cd "$W"

echo
echo "== 1. Generate a representative EC P-384 signing key and sign an artifact =="
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -outform DER -out signing-key.der 2>/dev/null
openssl pkey -in signing-key.der -inform DER -pubout -out signer.pub.pem 2>/dev/null
echo "  private key: $(wc -c < signing-key.der) bytes (high-entropy → safe to split directly)"
printf 'PostQuantum.SecretSharing release artifact' > artifact.bin
openssl dgst -sha384 -sign signing-key.der -keyform DER -out original.sig artifact.bin
echo "  signed a release artifact with the ORIGINAL key"

echo
echo "== 2. Split 3-of-5 (dealer-signed, ASCII-armored, with a commitment) =="
pqss split signing-key.der --k 3 --n 5 --out ./shares \
     --sign --sk-out ./dealer.key --armor --commit-out ./signing-key.commit

echo
echo "== 3. Verify every share before distribution (no quorum needed) =="
pqss verify ./shares/share-*.pqss.txt --pub ./shares/dealer.pub

echo
echo "== 4. Rehearse recovery without exposing the key (dry run) =="
pqss combine ./shares/share-1.pqss.txt ./shares/share-3.pqss.txt ./shares/share-5.pqss.txt \
     --pub ./shares/dealer.pub --commit ./signing-key.commit --dry-run

echo
echo "== 5. Real recovery from a DIFFERENT quorum (shares 2,4,5) =="
pqss combine ./shares/share-2.pqss.txt ./shares/share-4.pqss.txt ./shares/share-5.pqss.txt \
     --pub ./shares/dealer.pub --commit ./signing-key.commit --out recovered-key.der

echo
echo "== 6. Proof =="
if cmp -s signing-key.der recovered-key.der; then
  echo "  PROOF A: recovered key is BYTE-IDENTICAL to the original"
else
  echo "  PROOF A FAILED — keys differ!"; exit 1
fi
openssl dgst -sha384 -verify signer.pub.pem -signature original.sig artifact.bin >/dev/null
openssl dgst -sha384 -sign recovered-key.der -keyform DER -out new.sig artifact.bin
openssl dgst -sha384 -verify signer.pub.pem -signature new.sig artifact.bin >/dev/null
echo "  PROOF B: a NEW signature from the RECOVERED key verifies against the ORIGINAL public key"

echo
echo "Ceremony complete. The signing key can be reconstituted only by a quorum,"
echo "and survives reconstruction byte-for-byte. (Representative key; substitute"
echo "your real key per docs/CASE-STUDY-signing-key.md.)"

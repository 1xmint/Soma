#!/usr/bin/env bash
# Build the mirror bundle — everything needed to rebuild the protocol, and
# nothing else.
#
#   ./scripts/build-mirror-bundle.sh [output-dir]
#
# The bundle is what gets handed to a custodian who is not the author, to hold
# on infrastructure that is not the author's. It is deliberately tiny: a
# specification that references nothing, a drill that proves the specification
# is sufficient, and checksums so a copy can be checked without trusting
# whoever passed it on.
#
# This is a script rather than a committed snapshot because a stale mirror is
# worse than none — someone would trust it.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/mirror-bundle}"

rm -rf "$OUT"
mkdir -p "$OUT"

cp "$ROOT/GENESIS.md" "$OUT/"
cp "$ROOT/js/test/revival-drill.py" "$OUT/"

cat > "$OUT/README.md" <<'README'
# Somavera — mirror bundle

Everything needed to rebuild the protocol from nothing. Two files and a
checksum list.

## What this is

`GENESIS.md` is the specification. It references no file, repository or URL,
because a revival assumes none exist, and it names no programming language,
because languages die. It describes bytes and behaviour, which do not.

`revival-drill.py` is a working implementation built from that document alone.
It exists to prove the document is sufficient — a revival specification that has
never revived anything is a claim, not a capability.

## Verify this copy without trusting anyone

```
sha256sum -c SHA256SUMS
python3 revival-drill.py
```

The drill reproduces every vector in the specification and rejects everything it
should. If it passes, the document you are holding is intact and complete enough
to rebuild identity and canonical bytes from scratch.

**A document cannot authenticate itself**, and this one does not pretend to. What
it can do is be internally consistent: the vectors check each other and check any
implementation built from the prose. A tampered copy fails its own vectors.

## Why you have this

The protocol is meant to outlive its author, any organisation, and any code
hosting platform. That is only true if copies exist that none of those control.

You are not asked to maintain anything, agree to anything, or do anything. Hold
the file. If everything else disappears, it is enough.

## What a revival does not restore

No balances, no history, no reputation, no keys. Those live in state, not in a
specification. A revival from this bundle starts empty, and anyone claiming
otherwise is reconstructing something the document never held.

What survives is the ability to verify: that a signature was made by the party an
identifier names, over exactly the content claimed.
README

cd "$OUT"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum GENESIS.md revival-drill.py README.md > SHA256SUMS
else
  shasum -a 256 GENESIS.md revival-drill.py README.md > SHA256SUMS
fi

echo "bundle: $OUT"
echo
cat SHA256SUMS
echo
echo "total size: $(du -sh "$OUT" | cut -f1)"
echo
echo "Hand this to custodians who are not the author, on infrastructure that is"
echo "not the author's, in more than one jurisdiction. A mirror inside the same"
echo "organisation protects against nothing that organisation is exposed to."

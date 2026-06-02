#!/bin/bash
# Robuuste Slither-runner voor de scanner (draait in WSL Ubuntu 24.04).
# Args: $1 = WSL-pad naar contract-dir (/mnt/c/...), $2 = solc-versie
VENV=/home/moham/slither-venv
export PATH="$VENV/bin:$PATH"
DIR="$1"
VER="${2:-0.8.20}"
"$VENV/bin/solc-select" install "$VER" >/dev/null 2>&1 || true
cd "$DIR" 2>/dev/null || { echo "{}"; exit 0; }
OUT="/tmp/slither_$$.json"
# Poging 1: normaal
SOLC_VERSION="$VER" "$VENV/bin/slither" . --json "$OUT" >/dev/null 2>&1
if [ ! -s "$OUT" ]; then
  # Poging 2: via-ir + optimizer — lost 'Stack too deep' compilatiefouten op
  rm -f "$OUT"
  SOLC_VERSION="$VER" "$VENV/bin/slither" . --json "$OUT" --solc-args "--via-ir --optimize" >/dev/null 2>&1
fi
cat "$OUT" 2>/dev/null || echo "{}"
rm -f "$OUT"

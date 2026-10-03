#!/usr/bin/env bash
# Run the authors' evaluate.py (ATLAS) in one experiment-style folder, offline, in
# the Python 3.7 container; write everything it prints to LOG.
#   usage: run_eval.sh DIR LOG
set -uo pipefail
dir=$1
log=$2
mkdir -p "$(dirname "$log")"
timeout 5400 docker run --rm --network none -v "$dir:/exp" -w /exp atlas-eval:local python evaluate.py \
  > "$log.full" 2>&1
rc=$?
# evaluate.py prints every cleaned entity; keep the head (errors) and the tail (counts)
{ head -n 40 "$log.full" | cut -c1-2000; echo "..."; tail -n 60 "$log.full" | cut -c1-2000; } > "$log"
rm -f "$log.full"
[ "$rc" -eq 0 ] || echo "exit $rc" >> "$log"
echo "$(basename "$log"): rc=$rc"

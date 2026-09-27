#!/usr/bin/env bash
# Live capture inside a GitHub Actions Ubuntu runner (needs sudo).
# Benign background activity + a scripted "stage -> fetch -> archive -> clean up"
# sequence. No attack tooling, no exploit code; the only network peer is a
# python http.server bound to 127.0.0.1 inside the runner.
set -euo pipefail
OUT=${1:-live-out}
PORT=${PORT:-8765}
mkdir -p "$OUT" /tmp/rv /tmp/rv-www
echo "benign payload $(date -u +%s)" > /tmp/rv-www/data.txt

sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq auditd >/dev/null
sudo systemctl start auditd || sudo service auditd start
sudo auditctl -D
sudo auditctl -b 16384
sudo auditctl -a always,exit -F arch=b64 -S execve,execveat -k rv_exec
sudo auditctl -a always,exit -F arch=b64 -S connect -k rv_net
sudo auditctl -w /tmp/rv -p wa -k rv_file
sudo auditctl -l
START=$(date +%s)

python3 -m http.server "$PORT" --bind 127.0.0.1 --directory /tmp/rv-www >/dev/null 2>&1 &
SRV=$!
sleep 2

# --- benign background noise -------------------------------------------------
( for i in 1 2 3; do ls -la /usr/share >/dev/null; uname -a >/dev/null; id >/dev/null;
    python3 -c 'import json,sys; json.dumps({"x": 1})'; git --version >/dev/null;
    python3 -c "open('/tmp/rv/cache-$i.tmp', 'w').write('x')";
    curl -s -o /dev/null "http://127.0.0.1:${PORT}/"; rm -f "/tmp/rv/cache-$i.tmp"; sleep 1; done ) &
NOISE=$!

# --- scripted sequence (ground truth recorded below) --------------------------
cat > /tmp/scenario.sh <<SCEN
#!/usr/bin/env bash
set -e
cp /usr/bin/curl /tmp/rv/fetcher
chmod +x /tmp/rv/fetcher
/tmp/rv/fetcher -s -o /tmp/rv/loot.txt http://127.0.0.1:${PORT}/data.txt
tar -czf /tmp/rv/out.tgz -C /tmp/rv loot.txt
rm -f /tmp/rv/loot.txt
SCEN
chmod +x /tmp/scenario.sh
bash /tmp/scenario.sh
wait "$NOISE"
sleep 2
kill "$SRV" || true
sudo auditctl -D
sleep 1
sudo ausearch --raw --start "$(date -d @"$START" '+%m/%d/%Y %H:%M:%S')" > "$OUT/audit.log" || sudo cp /var/log/audit/audit.log "$OUT/audit.log"
sudo chown "$(id -u)" "$OUT/audit.log"
cat > "$OUT/ground_truth.json" <<GT
{"host": "$(hostname -s)", "port": $PORT, "scenario": "/tmp/scenario.sh",
 "dropped_image": "/tmp/rv/fetcher", "fetched_file": "/tmp/rv/loot.txt",
 "archive": "/tmp/rv/out.tgz", "peer": "127.0.0.1:$PORT"}
GT
wc -l "$OUT/audit.log"

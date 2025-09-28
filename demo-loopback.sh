#!/usr/bin/env bash
# demo-loopback.sh
# Safe loopback-only demo script for network-packet-analyzer (interface: lo / 127.0.0.1)
# Run this from a SECOND terminal while analyzer is running and capturing on interface 0 (lo).
# Usage:
#   chmod +x demo-loopback.sh
#   ./demo-loopback.sh

set -eu
echo "=== demo-loopback.sh: starting demo (loopback-only) ==="
echo "Note: run this in a DIFFERENT terminal than the analyzer (which must be running and set to interface 0)."
echo

# helper to spawn background job and track PID
bg_pids=()
bg_spawn() {
  "$@" >/dev/null 2>&1 &
  bg_pids+=($!)
}

# 1) TCP test (HTTPS request)
echo "1) TCP test (HTTPS request via curl to external host; analyzer may see this only on non-lo interfaces)"
# keep but optional; if you want strictly loopback-only, comment out the next line
curl -s -o /dev/null -w "HTTP status: %{http_code}\n" https://www.google.com || true
sleep 1

# 2) UDP test - send a UDP packet to localhost port 9999
echo
echo "2) UDP test (send simple UDP packet to 127.0.0.1:9999)"
python3 - <<'PY' || true
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"udp-test-loopback", ("127.0.0.1", 9999))
s.close()
PY
sleep 1

# 3) ICMP test (ping loopback)
echo
echo "3) ICMP test (ping loopback 127.0.0.1)"
ping -c 4 127.0.0.1 || true
sleep 1

# 4) Suspicious port test (no listener -> connection refused)
echo
echo "4) Suspicious port test (connect to 127.0.0.1:4444 - expected: Connection refused if no listener)"
nc -vz 127.0.0.1 4444 || true
sleep 1

# 4b) Start a simple HTTP listener on 4444 so we can show successful connect
echo
echo "4b) Start a simple HTTP listener on 127.0.0.1:4444 (background)"
nohup python3 -m http.server 4444 >/dev/null 2>&1 &
PID_HTTP=$!
echo "Listener PID: $PID_HTTP"
sleep 1

echo "Try connecting to the listener (curl -> should succeed)"
curl -s -I http://127.0.0.1:4444 || true
sleep 1

# Stop the listener cleanly
echo "Stopping listener (PID: $PID_HTTP)"
kill $PID_HTTP || true
sleep 1

# 5) Port scan test - try nmap if available, otherwise fallback to nc loop
echo
echo "5) Port scan test (ports 1-20) - using nmap if installed, otherwise fallback"
if command -v nmap >/dev/null 2>&1; then
  echo "Running: nmap -p 1-20 127.0.0.1"
  nmap -p 1-20 127.0.0.1 || true
else
  echo "nmap not found — using nc fallback (sequential connections to ports 1..20)"
  for p in $(seq 1 20); do
    nc -z -v 127.0.0.1 $p || true
  done
fi
sleep 1

# 6) Simulated many connects (controlled) - attempts many short connections to many ports on loopback
echo
echo "6) Simulated many connects (safe loopback) to try to trigger DoS / port-scan detection"
echo "This will spawn background nc probes — it is local-only and controlled (100 attempts)."
for i in $(seq 1 100); do
  nc -z 127.0.0.1 $((11000 + (i % 100))) >/dev/null 2>&1 &
  bg_pids+=($!)
done

# Wait for background probes to complete (with timeout safety)
sleep 2
# try to reap bg pids
for pid in "${bg_pids[@]:-}"; do
  if kill -0 "$pid" 2>/dev/null; then
    wait "$pid" 2>/dev/null || true
  fi
done

echo
echo "=== Demo finished. Give the analyzer a few seconds to print alerts, then stop it with Ctrl+C (in analyzer terminal). ==="
echo "Capture file will be saved as capture.pcap after you stop the analyzer."

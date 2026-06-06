#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -n "${PYTHON:-}" ]]; then
  PYTHON_BIN="$PYTHON"
elif [[ -x ".venv/bin/python" ]]; then
  PYTHON_BIN=".venv/bin/python"
else
  PYTHON_BIN="python"
fi

TMP_DIR="$(mktemp -d)"
REMOTE_PID=""

cleanup() {
  if [[ -n "$REMOTE_PID" ]]; then
    kill "$REMOTE_PID" >/dev/null 2>&1 || true
    wait "$REMOTE_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

run_expected_failure() {
  set +e
  "$@"
  status=$?
  set -e
  if [[ "$status" -ne 1 ]]; then
    echo "expected exit 1, got $status: $*" >&2
    exit 1
  fi
}

verify_json_contract() {
  local report_path="$1"
  "$PYTHON_BIN" - "$report_path" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text())
findings = payload.get("findings", [])
if not findings:
    raise SystemExit(f"{path} did not contain findings")
if not all(finding.get("payload_stored") is False for finding in findings):
    raise SystemExit(f"{path} contains a finding without payload_stored=false")

raw = path.read_text()
blocked_fragments = [
    "ghp_abcdefghijklmnopqrstuvwxyz123456",
    "not actually running",
    "results for ",
]
for fragment in blocked_fragments:
    if fragment in raw:
        raise SystemExit(f"{path} contains raw fixture payload fragment: {fragment}")

print(f"{path}: {len(findings)} findings, payload_stored=false verified")
PY
}

wait_for_port() {
  local port="$1"
  "$PYTHON_BIN" - "$port" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        if sock.connect_ex(("127.0.0.1", port)) == 0:
            sys.exit(0)
    time.sleep(0.05)
raise SystemExit(f"remote fixture did not listen on port {port}")
PY
}

choose_port() {
  "$PYTHON_BIN" - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

echo "== list checks =="
"$PYTHON_BIN" -m mcpscan list-checks >/dev/null

echo "== benign stdio fixture =="
"$PYTHON_BIN" -m mcpscan scan --command "$PYTHON_BIN tests/fixtures/benign_server.py" >/dev/null

echo "== malicious stdio fixture =="
run_expected_failure "$PYTHON_BIN" -m mcpscan scan \
  --command "$PYTHON_BIN tests/fixtures/malicious_server.py" \
  --severity-threshold high

MALICIOUS_JSON="$TMP_DIR/malicious.json"
run_expected_failure "$PYTHON_BIN" -m mcpscan scan \
  --command "$PYTHON_BIN tests/fixtures/malicious_server.py" \
  --output json \
  --out "$MALICIOUS_JSON"
verify_json_contract "$MALICIOUS_JSON"

echo "== local Streamable HTTP fixture =="
PORT="$(choose_port)"
"$PYTHON_BIN" tests/fixtures/remote_streamable_server.py --port "$PORT" \
  >"$TMP_DIR/remote-fixture.log" 2>&1 &
REMOTE_PID="$!"
wait_for_port "$PORT"

REMOTE_JSON="$TMP_DIR/remote.json"
run_expected_failure "$PYTHON_BIN" -m mcpscan scan \
  "http://127.0.0.1:$PORT/mcp" \
  --transport http \
  --output json \
  --out "$REMOTE_JSON"
verify_json_contract "$REMOTE_JSON"

echo "validation smoke passed"

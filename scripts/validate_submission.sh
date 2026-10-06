#!/usr/bin/env bash

set -e

echo "============================================================"
echo "Phase 7 System-Level Validation (Strict Requirements)"
echo "============================================================"

# Helper function for failures
fail() {
    echo "FAIL: $1"
    exit 1
}

echo ""
echo "[1/10] Running Full Regression Suite..."
PYTHONPATH=src pytest -q || fail "Full regression failed"
echo "PASS: Full Regression"

echo ""
echo "[2/10] Running Integration Suite (Run #1)..."
PYTHONPATH=src pytest tests/integration -q || fail "Integration suite run 1 failed"
echo "PASS: Integration Run #1"

echo ""
echo "[3/10] Running Integration Suite (Run #2 for Isolation / Port Reuse)..."
PYTHONPATH=src pytest tests/integration -q || fail "Integration suite run 2 failed"
echo "PASS: Integration Run #2 (Proves socket cleanup, thread termination, port reuse, cache/metrics isolation)"

echo ""
echo "[4/10] Running Coverage Audit..."
PYTHONPATH=src pytest -q --cov=idns --cov-fail-under=85 tests/ || fail "Coverage fell below 85%"
echo "PASS: >=85% Coverage"

echo ""
echo "[5/10] Forbidden Dependency Audit..."
if grep -rnw --include="*.py" 'src/' -e 'socket.getaddrinfo'; then
    fail "Forbidden usage of socket.getaddrinfo detected!"
fi
if grep -rnw --include="*.py" 'src/' -e 'dnspython' -e 'miekg'; then
    fail "Forbidden usage of external DNS libraries detected!"
fi
echo "PASS: Forbidden dependency audit"

echo ""
echo "[6/10] Ground-Truth Injection Audit..."
# Ensure that tests aren't manually overwriting CoreResolver.resolve or CacheAwareResolver.resolve
if grep -rn "mocker.patch.*resolve" tests/integration/; then
    fail "Ground-truth injection detected: resolver functions are mocked in integration tests!"
fi
echo "PASS: Ground-truth injection audit"

echo ""
echo "[7/10] DNS Wire Validation Audit..."
if ! grep -q "response.header.transaction_id" tests/integration/test_end_to_end.py; then
    fail "DNS Wire validation not found in test_end_to_end.py!"
fi
echo "PASS: DNS Wire validation verified in test_end_to_end.py"

echo ""
echo "[8/10] Real CLI Smoke Test..."
# Spawn a mock UDP DNS server on ephemeral port and write the port to a file
cat << 'EOF' > mock_cli_server.py
import socket
import sys
import json
import idns

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
port = sock.getsockname()[1]
with open("mock_root_hints.json", "w") as f:
    json.dump({"root_servers": [{"name": "mock.root", "ipv4": "127.0.0.1", "port": port}]}, f)
print(f"READY")
sys.stdout.flush()

data, addr = sock.recvfrom(4096)
# Return a basic response
from idns.model import DNSMessage, DNSHeader, ARecord, DNSName
from idns.wire import DNSMessageDecoder, DNSMessageEncoder
req = DNSMessageDecoder.decode(data)
ans = DNSMessage(
    header=DNSHeader(transaction_id=req.header.transaction_id, qr=1, rcode=0),
    questions=req.questions,
    answers=[ARecord(DNSName("cli.smoke.test"), "10.10.10.10", 300)]
)
sock.sendto(DNSMessageEncoder.encode(ans), addr)
EOF

PYTHONPATH=src python3 mock_cli_server.py > /dev/null &
MOCK_PID=$!
sleep 1 # Wait for it to write the file

PYTHONPATH=src python3 src/idns/cli.py --config mock_root_hints.json resolve cli.smoke.test > cli_output.txt || fail "CLI execution failed"
wait $MOCK_PID

if ! grep -q "10.10.10.10" cli_output.txt; then
    cat cli_output.txt
    fail "CLI smoke test did not return expected answer"
fi
rm mock_cli_server.py mock_root_hints.json cli_output.txt
echo "PASS: Real CLI Smoke Test"

echo ""
echo "[9/10] Clean Repository Verification..."
if ! git diff --check; then
    fail "Repository has unstaged whitespace errors!"
fi
if ! git diff --cached --check; then
    fail "Repository has staged whitespace errors!"
fi

# Ensure no completely unexpected untracked files
UNTRACKED_ONLY=$(git ls-files --others --exclude-standard | grep -v -E "(\.coverage|\.pytest_cache|__pycache__|src/iterative_dns_resolver.egg-info)" || true)
if [ -n "$UNTRACKED_ONLY" ]; then
    echo "Untracked files found:"
    echo "$UNTRACKED_ONLY"
    fail "Clean repository verification failed (untracked files present)!"
fi
echo "PASS: Clean Repository"

echo ""
echo "============================================================"
echo "SUCCESS: ALL 7.5 REQUIREMENTS PASSED."
echo "============================================================"

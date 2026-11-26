#!/usr/bin/env bash
set -euo pipefail

BIN="${KREAMLINK_BIN:-./kreamlink}"
TMPDIR="$(mktemp -d)"

cleanup() {
    local status=$?
    local running
    running=$(jobs -pr)
    for p in $running; do kill "$p" 2>/dev/null || true; done
    for p in $running; do wait "$p" 2>/dev/null || true; done
    if ((status != 0)); then
        for log in "$TMPDIR"/*.log; do
            if [[ -f "$log" ]]; then tail -n 12 "$log" >&2; fi
        done
    fi
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

wait_log() {
    local pid=$1 log=$2 match=$3 i
    for ((i=0; i<150; i++)); do
        kill -0 "$pid" 2>/dev/null || return 1
        if grep -Fq -- "$match" "$log"; then return 0; fi
        sleep 0.1
    done
    echo "Timed out waiting for '$match' in $log" >&2
    return 1
}

wait_tunnel() {
    python3 - "$1" <<'PYREADY'
import socket, sys, time
port = int(sys.argv[1])
deadline = time.monotonic() + 15
while time.monotonic() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1) as s:
            s.sendall(b"ready")
            s.shutdown(socket.SHUT_WR)
            with s.makefile("rb") as reader:
                if reader.read() == b"ECHO:ready":
                    break
    except OSError:
        pass
    time.sleep(0.1)
else:
    raise SystemExit("Tunnel did not become ready")
PYREADY
}

echo "[1/7] Starting target TCP echo service on 127.0.0.1:19222..."
python3 -u -c '
import socket, threading, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 19222))
s.listen(64)
print("target ready")
def handle(c):
    try:
        chunks = []
        total = 0
        while True:
            d = c.recv(4096)
            if not d: break
            chunks.append(d)
            total += len(d)
            if total <= 16:
                command = b"".join(chunks)
                if command == b"probe-stream":
                    c.sendall(b"OK")
                    while True:
                        probe = c.recv(128)
                        if not probe: return
                        c.sendall(probe)
                if command == b"slow-source":
                    c.sendall(b"OK")
                    if c.recv(1) != b"G": return
                    for _ in range(2048):
                        c.sendall(bytes(16384))
                        time.sleep(0.002)
                    return
                if command == b"slow-sink":
                    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                    c.sendall(b"OK")
                    time.sleep(15)
                    return
            if total == len(b"keep-open") and b"".join(chunks) == b"keep-open":
                c.sendall(b"OK")
        c.sendall(b"ECHO:" + b"".join(chunks))
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
' >"$TMPDIR/target.log" 2>&1 &
wait_log "$!" "$TMPDIR/target.log" "target ready"

echo "[2/7] Starting kreamlink Hub on 127.0.0.1:19080..."
"$BIN" hub -l 127.0.0.1:19080 --path /api/v1/stream --subprotocol kream.v1 >"$TMPDIR/hub.log" 2>&1 &
HUB_PID=$!
wait_log "$HUB_PID" "$TMPDIR/hub.log" "Hub listening"

echo "[3/7] Testing Layer-1 anti-probing decoy response..."
python3 -c '
import socket
s = socket.create_connection(("127.0.0.1", 19080), timeout=3)
s.sendall(b"GET /api/v1/stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
resp = s.makefile("rb").read().decode()
s.close()
assert "200 OK" in resp and "\"status\":\"ok\"" in resp, f"Unexpected probe resp: {resp}"
print("  -> Anti-probe decoy OK")
'

echo "[4/7] Starting Receiver (permanent port holder on 127.0.0.1:19122) BEFORE Sender is online..."
"$BIN" recv -u ws://127.0.0.1:19080/api/v1/stream -k super-secret-chan -l 127.0.0.1:19122 --subprotocol kream.v1 --wait-peer 500 >"$TMPDIR/recv.log" 2>&1 &
RECV_PID=$!
wait_log "$RECV_PID" "$TMPDIR/recv.log" "Receiver holding local port"

# Verify port 19122 is already held by Receiver even though Sender is NOT online yet
python3 -c '
import errno, socket
s = socket.socket()
try:
    s.bind(("127.0.0.1", 19122))
    raise AssertionError("Port 19122 should already be occupied by Receiver!")
except OSError as e:
    assert e.errno == errno.EADDRINUSE, e
    print("  -> Confirmed: Receiver holds port 19122 permanently while Sender is offline")
finally:
    s.close()
'

echo "[5/7] Starting Sender, testing concurrent E2EE streams + Sender disconnect/reconnect recovery..."
"$BIN" send -u ws://127.0.0.1:19080/api/v1/stream -k super-secret-chan -t 127.0.0.1:19222 --subprotocol kream.v1 >"$TMPDIR/send.log" 2>&1 &
SEND_PID=$!
wait_log "$SEND_PID" "$TMPDIR/send.log" "Connected to Hub"
wait_tunnel 19122

python3 -c '
import socket, concurrent.futures

def roundtrip(i):
    payload = f"hello-kreamlink-{i}-" + ("X" * (i * 512))
    s = socket.create_connection(("127.0.0.1", 19122), timeout=5)
    s.sendall(payload.encode())
    s.shutdown(socket.SHUT_WR)
    chunks = []
    while True:
        d = s.recv(4096)
        if not d: break
        chunks.append(d)
    s.close()
    got = b"".join(chunks).decode()
    assert got == "ECHO:" + payload, f"Mismatch on stream {i}: len={len(got)}"

with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
    futs = [ex.submit(roundtrip, i) for i in range(1, 9)]
    for f in futs:
        f.result()
print("  -> 8 concurrent E2EE multiplexed streams passed!")
'

python3 tests/test_slow_stream.py 19122 "$TMPDIR/recv.log" "$TMPDIR/send.log"

echo "  -> Simulating Sender disconnect & reconnect while Receiver keeps port 19122 held..."
kill "$SEND_PID"
wait "$SEND_PID"

# Port 19122 must STILL be held by Receiver!
python3 -c '
import errno, socket
s = socket.socket()
try:
    s.bind(("127.0.0.1", 19122))
    raise AssertionError("Port 19122 was released when Sender disconnected!")
except OSError as e:
    assert e.errno == errno.EADDRINUSE, e
    print("  -> Confirmed: Receiver kept port 19122 occupied during Sender outage")
finally:
    s.close()
'

# Bring Sender back online
"$BIN" send -u ws://127.0.0.1:19080/api/v1/stream -k super-secret-chan -t 127.0.0.1:19222 --subprotocol kream.v1 >"$TMPDIR/send2.log" 2>&1 &
SEND2_PID=$!
wait_log "$SEND2_PID" "$TMPDIR/send2.log" "Connected to Hub"
wait_tunnel 19122

python3 -c '
import socket
s = socket.create_connection(("127.0.0.1", 19122), timeout=5)
s.sendall(b"recovered-after-sender-reconnect")
s.shutdown(socket.SHUT_WR)
got = s.makefile("rb").read()
s.close()
assert got == b"ECHO:recovered-after-sender-reconnect", f"Got: {got}"
print("  -> Tunnel auto-recovered immediately after Sender reconnected!")
'

echo "  -> Testing WSS (TLS 1.2/1.3) direct mode with self-signed certificate..."
openssl req -x509 -newkey rsa:2048 -keyout "$TMPDIR/key.pem" -out "$TMPDIR/cert.pem" \
    -days 1 -nodes -config tests/test_cert.cnf 2>/dev/null

"$BIN" hub -l 127.0.0.1:19443 --path /wss/stream --tls-cert "$TMPDIR/cert.pem" --tls-key "$TMPDIR/key.pem" >"$TMPDIR/hub_tls.log" 2>&1 &
TLS_HUB_PID=$!
wait_log "$TLS_HUB_PID" "$TMPDIR/hub_tls.log" "Hub listening"

SSL_CERT_FILE="$TMPDIR/cert.pem" "$BIN" recv -u wss://127.0.0.1:19443/wss/stream -k tls-secret -l 127.0.0.1:19422 >"$TMPDIR/recv_tls.log" 2>&1 &
TLS_RECV_PID=$!
SSL_CERT_FILE="$TMPDIR/cert.pem" "$BIN" send -u wss://127.0.0.1:19443/wss/stream -k tls-secret -t 127.0.0.1:19222 >"$TMPDIR/send_tls.log" 2>&1 &
TLS_SEND_PID=$!
wait_log "$TLS_SEND_PID" "$TMPDIR/send_tls.log" "Connected to Hub"
wait_tunnel 19422

python3 -c '
import socket
s = socket.create_connection(("127.0.0.1", 19422), timeout=5)
s.sendall(b"wss-tls-e2ee-works")
s.shutdown(socket.SHUT_WR)
got = s.makefile("rb").read()
s.close()
assert got == b"ECHO:wss-tls-e2ee-works", f"Got: {got}"
print("  -> WSS (TLS) + E2EE tunnel passed!")
'

# Stop the receiver with a proven live, bidirectional stream and require clean exit.
python3 - "$TLS_RECV_PID" <<'PYSTOP'
import os, signal, socket, sys
with socket.create_connection(("127.0.0.1", 19422), timeout=5) as s:
    s.sendall(b"keep-open")
    with s.makefile("rb") as reader:
        assert reader.read(2) == b"OK"
        os.kill(int(sys.argv[1]), signal.SIGTERM)
        assert reader.read(1) == b""
PYSTOP
wait "$TLS_RECV_PID"
kill "$TLS_SEND_PID" "$TLS_HUB_PID"
wait "$TLS_SEND_PID"
wait "$TLS_HUB_PID"

echo "[6/7] Testing Hub outage + restart auto-recovery (Receiver port stays held) & 4MB backpressure..."
kill "$HUB_PID"
wait "$HUB_PID"

# Port 19122 must STILL be held by Receiver while Hub is completely down!
python3 -c '
import errno, socket
s = socket.socket()
try:
    s.bind(("127.0.0.1", 19122))
    raise AssertionError("Port 19122 was released when Hub went down!")
except OSError as e:
    assert e.errno == errno.EADDRINUSE, e
    print("  -> Confirmed: Receiver kept port 19122 occupied during complete Hub outage")
finally:
    s.close()
'

# Restart Hub on the same address
"$BIN" hub -l 127.0.0.1:19080 --path /api/v1/stream --subprotocol kream.v1 >"$TMPDIR/hub2.log" 2>&1 &
HUB2_PID=$!
wait_log "$HUB2_PID" "$TMPDIR/hub2.log" "Hub listening"
wait_tunnel 19122

# Verify 4MB binary stream integrity over recovered tunnel (tests backpressure + zero dropped frames)
python3 -c '
import hashlib, os, socket
data = os.urandom(4 * 1024 * 1024)
expected = hashlib.sha256(b"ECHO:" + data).hexdigest()
s = socket.create_connection(("127.0.0.1", 19122), timeout=20)
s.sendall(data)
s.shutdown(socket.SHUT_WR)
h = hashlib.sha256()
total = 0
while True:
    chunk = s.recv(65536)
    if not chunk: break
    h.update(chunk)
    total += len(chunk)
s.close()
assert total == len(data) + 5, f"Expected {len(data)+5} bytes, got {total}"
assert h.hexdigest() == expected, "SHA256 mismatch on 4MB stream!"
print("  -> Hub restart auto-recovery + 4MB E2EE backpressure stream integrity PASSED!")
'

echo "[7/7] Testing silent blackhole / half-open TCP watchdog detection..."
python3 -u -c '
import base64, hashlib, socket, time

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 19099))
s.listen(4)
s.settimeout(12)
print("fixture ready")

def accept_ws_and_blackhole(conn):
    conn.settimeout(5)
    req = b""
    while b"\r\n\r\n" not in req:
        chunk = conn.recv(4096)
        if not chunk: raise EOFError("Incomplete HTTP request")
        req += chunk
    key = ""
    for line in req.decode().split("\r\n"):
        if line.lower().startswith("sec-websocket-key:"):
            key = line.split(":", 1)[1].strip()
    acc = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
    conn.sendall(f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {acc}\r\n\r\n".encode())
    # Read subscribe text frame (ignore payload) and send ok reply
    conn.recv(4096)
    reply = b"{\"status\":\"ok\",\"session\":\"deadbeef\",\"peer_online\":false}"
    conn.sendall(bytes([0x81, len(reply)]) + reply)
    # Now SILENTLY BLACKHOLE: never send pong, never close!

# First connection gets blackholed; expect Agent watchdog to reconnect within ~5s!
c1, _ = s.accept()
accept_ws_and_blackhole(c1)
c2, _ = s.accept()
c2.close()
c1.close()
s.close()
print("  -> Confirmed: Agent detected silent blackhole via monotonic watchdog and reconnected!")
' >"$TMPDIR/fixture.log" 2>&1 &
BH_PID=$!
wait_log "$BH_PID" "$TMPDIR/fixture.log" "fixture ready"

"$BIN" recv -u ws://127.0.0.1:19099/api/v1/stream -k bh-test -l 127.0.0.1:19199 --heartbeat 1 >"$TMPDIR/bh_recv.log" 2>&1 &
BH_RECV_PID=$!

wait "$BH_PID"
grep -Fq "Hub link silent" "$TMPDIR/bh_recv.log"
kill "$BH_RECV_PID"
wait "$BH_RECV_PID"

kill "$RECV_PID" "$SEND2_PID" "$HUB2_PID"
wait "$RECV_PID"
wait "$SEND2_PID"
wait "$HUB2_PID"
echo "ALL TESTS PASSED!"

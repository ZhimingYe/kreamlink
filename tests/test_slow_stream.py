"""Two streams on the existing e2e tunnel. Keep the same probe socket throughout."""
from concurrent.futures import ThreadPoolExecutor
import socket
import sys
import time
from pathlib import Path

PORT = int(sys.argv[1])
MARKER = "local write buffer unavailable or full"


def recv_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise AssertionError("Established stream closed")
        result.extend(chunk)
    return result


def fill_slow_target(sock):
    try:
        for _ in range(2048):
            sock.sendall(bytes(16384))
            time.sleep(0.002)
    except (BrokenPipeError, ConnectionResetError):
        return True
    return False


def check(direction, log):
    with socket.create_connection(("127.0.0.1", PORT), timeout=2) as healthy:
        healthy.sendall(b"probe-stream")
        assert recv_exact(healthy, 2) == b"OK"
        before = log.read_bytes().count(MARKER.encode())
        with socket.socket() as slow, ThreadPoolExecutor(max_workers=1) as pool:
            slow.settimeout(3)
            slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            slow.connect(("127.0.0.1", PORT))
            slow.sendall(b"slow-source" if direction == "Receiver" else b"slow-sink")
            assert recv_exact(slow, 2) == b"OK"

            writer = None
            if direction == "Receiver":
                slow.sendall(b"G")
            else:
                writer = pool.submit(fill_slow_target, slow)

            deadline = time.monotonic() + 10
            probes = 0
            worst = 0.0
            while True:
                # Include a round trip after the isolation event on the original socket.
                reset = log.read_bytes().count(MARKER.encode()) > before
                payload = str(probes).encode()
                start = time.monotonic()
                healthy.sendall(payload)
                assert recv_exact(healthy, len(payload)) == payload
                worst = max(worst, time.monotonic() - start)
                probes += 1
                if reset:
                    break
                if time.monotonic() >= deadline:
                    raise AssertionError(f"{direction} did not isolate its stalled stream")
                time.sleep(0.025)

            # Either direction may observe the TCP reset first.
            saw_reset = writer.result(timeout=6) if writer else False
            try:
                while slow.recv(65536):
                    if time.monotonic() >= deadline + 3:
                        raise AssertionError("Slow connection still receiving data")
            except ConnectionResetError:
                saw_reset = True
            assert saw_reset, "Truncated stream ended with a clean EOF"
        print(f"  -> {direction} isolated slow stream; {probes} probes, "
              f"max observed round trip {worst * 1000:.1f} ms")


if __name__ == "__main__":
    check("Receiver", Path(sys.argv[2]))
    check("Sender", Path(sys.argv[3]))

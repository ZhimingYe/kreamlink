# Working on kreamlink

These instructions apply throughout the repository. Keep [README.md](README.md) focused on what users can do, how to start the three roles, and what happens during an outage. Keep implementation and regression-test guidance here. Write both documents in English.

## Where to make changes

| Area | Files |
| --- | --- |
| CLI, defaults, configuration parsing | `src/main.c`, `src/config.c`, `examples/*.yaml` |
| Receiver listener, Sender dialing, stream workers and local buffering | `src/agent.c` |
| Hub pairing, peer replacement and relay queues | `src/hub.c` |
| TCP, TLS and WebSocket I/O | `src/ws.c` |
| Control messages, channel IDs and encrypted frames | `src/control.c`, `src/crypto.c` |
| Worker slots, shared types and limits | `src/workers.c`, `include/kreamlink.h` |

The Makefile and CMakeLists.txt each list the C sources explicitly. Keep both lists in sync when adding or removing a source file. Both builds target C11 on Linux and macOS.

## HTTPS termination and proxy compatibility

Operators choose where HTTPS terminates and how to protect the connection to the Hub. Keep the Hub compatible with any deployment that delivers a standard HTTP/1.1 WebSocket upgrade on the configured path. Keep setup instructions proxy-neutral. Direct TLS on the Hub remains an operator choice.

Authenticate both roles using the Hub password in the first WebSocket registration message. Treat `Forwarded`, `X-Forwarded-Proto`, cookies, and User-Agent as untrusted metadata. Their presence, absence, or values must not change registration or authorization. Negotiate a subprotocol only when both sides offer a match.

When changing the handshake, exercise requests with absent and conflicting forwarding headers and with no subprotocol offer. These cases are covered by [the end-to-end tests](tests/test_e2e.sh).

## Invariants to preserve

- **Listener lifetime.** The Receiver owns its listening socket across pairing and reconnect attempts. A Hub outage or replacement of a peer ends the old streams. Verify that the original port stays bound and that a fresh connection succeeds after pairing.
- **Per-stream I/O.** The WebSocket dispatcher publishes incoming bytes to a bounded, single-producer buffer. Only the stream's worker consumes those bytes and writes them to its local socket. Keep local socket I/O and final descriptor cleanup outside the session mutex. The last reference owns cleanup.
- **Backpressure and EOF.** Each stream allocates its 1 MiB buffer on demand. Reset that stream if the next frame cannot fit or if its worker has pending bytes and makes no write progress for 15 seconds. Deliver queued bytes before an orderly EOF and preserve the reverse direction after a half-close. A worker paused outside shared locks occupies one slot. A stalled dispatcher or a permanently held session lock affects the whole session.
- **Capacity.** The Hub and each agent have 128 worker slots per process. Each Hub client's outbound queue is bounded by both 8 MiB and 2,048 frames. Exercise the relevant limit at the stream or connection level when changing queue handling.
- **Secret inputs.** Prefer environment injection in user-facing examples. File-based credentials use separate regular files owned by the runtime UID with mode `0400` or `0600`. Verify permissions on the open descriptor. Keep secret values out of command lines and diagnostics.
- **Configuration compatibility.** Check the Hub password for both roles before registering a client or changing a pair. An omitted `allowed_tokens` allows authenticated agents to use any channel. A configured list requires at least one item. A 64-character lowercase hexadecimal value is read as a channel ID. Its derivation is the lowercase hex SHA-256 digest of the bytes of `kreamlink:channel-id:v1:` followed by the channel secret. Keep the examples and parser tests in sync with configuration changes.

## Verify a change

Run commands from the repository root. The test scripts use Bash and the OpenSSL CLI. The end-to-end suite also uses Python 3 and fixed TCP loopback ports, so run one copy at a time.

| Command | Coverage |
| --- | --- |
| `make test-unit` | Builds the binary and core test program, checks example and invalid configurations, and exercises framing, TLS verification, pairing, and stream lifecycle. |
| `make tests/test_core && ./tests/test_core --test-isolation` | Pauses one worker while another stream completes, checks ordered delivery after resume and counter wrap, and waits for the real write-stall deadline. |
| `make test` | Runs the unit tests, listener and isolation checks, then the loopback suite with all three roles, including slow readers on both ends, disconnects, reconnects, and shutdown. |

For stream-isolation changes, keep the healthy probe on the same established connection before, during, and after the slow stream stalls. Reconnecting the probe would hide a session reset. See [the slow-stream regression](tests/test_slow_stream.py) and [the end-to-end harness](tests/test_e2e.sh).

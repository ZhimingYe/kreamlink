# kreamlink protocol v1

A Receiver and a Sender each open a WebSocket connection to the Hub. Text messages register the two roles and report connection state. Once paired, the Hub forwards each binary message to the other agent with its payload unchanged. Each binary message carries one encrypted command for one TCP stream. Several streams can share a pair of WebSocket connections.

## Transport and pairing

Both agents are WebSocket clients. They mask outbound WebSocket frames, and the Hub sends unmasked frames. The implementation accepts fragmented data messages up to 65,536 bytes after reassembly. With WSS, TLS protects each agent's connection to its TLS endpoint. The encrypted binary records described below extend between the agents.

The Hub accepts a standard HTTP/1.1 WebSocket upgrade on its configured path. External HTTPS termination is a deployment choice. Forwarding headers, cookies, and the User-Agent have no role in registration or authorization. A configured Hub subprotocol is selected only when the client offers it. If there is no match, the Hub omits the subprotocol field from its upgrade response. Older Hub configurations that specified a cookie now use the registration password as their access control.

Control messages are flat JSON objects. Values can be unescaped strings, booleans, or decimal integers. The parser rejects embedded NUL bytes, nested structures, and duplicate recognized fields. Field order is immaterial.

| Exchange | Fields and behavior |
| --- | --- |
| Agent registers | The first message is at most 1,024 bytes of text with `action="subscribe"`, `role="recv"` or `"send"`, and `channel` set to the 64-character lowercase hexadecimal channel ID. The required string `hub_auth` is standard padded Base64 of the configured Hub password bytes. The reference agent also sends optional `topic` and `ts`. |
| Hub accepts | The reply contains `status="ok"`, `authenticated=true`, a random 32-character hexadecimal `session` string, and a boolean `peer_online`. The session string is informational. |
| Hub rejects | An invalid registration object receives `status="error"` and numeric `code=400`. A missing or incorrect password, or a channel rejected by the allowlist, receives `code=403`. The Hub then closes the connection. |
| Peer arrives | The waiting agent receives `{"type":"peer","online":true}`. The arriving agent learns the peer's state from its registration reply. |
| Heartbeat | The agent sends a text message with `type="ping"` and an integer Unix timestamp `ts`. The Hub replies with `type="pong"` and its own timestamp. WebSocket control-frame ping and pong are handled separately. |

During registration each endpoint accepts at most 16 WebSocket frames per message, including intervening control frames, within a single read deadline. The password is a reusable credential shared with the Hub. Base64 is reversible, so cross-machine registration requires verified WSS. The TLS termination point must be trusted. Agents require the authentication acknowledgment and reject legacy success replies. The password check applies to both roles and precedes channel lookup and peer replacement. Either role may arrive first.

A channel has one slot per role. When a paired agent disconnects, the Hub closes the surviving connection too. Registering a replacement for an occupied role retires the old pair. Connections registered afterward form a new pairing. TCP streams end with their pairing, and the Receiver keeps its local listener open across reconnects.

The reference agent sends a heartbeat every 15 seconds by default and reconnects after three heartbeat intervals without receiving traffic. The Hub separately expires idle clients after about 90 seconds. The peers do not negotiate these timers.

## Channel ID and encryption key

Let `secret` be the bytes of the configured channel secret. The literal strings below are ASCII, without a terminating NUL.

```text
channel_id = lowercase_hex(SHA256("kreamlink:channel-id:v1:" || secret))
key        = HKDF-SHA256(ikm=secret, salt="kreamlink-e2ee-salt-v1",
                         info="kreamlink-aes256gcm-key-v1", length=32)
```

Here `||` denotes byte concatenation. Registration sends the channel ID. Both agents independently derive the same AES-256-GCM key and use it in both directions. The registration session string does not participate in key derivation.

## Binary record

One WebSocket binary message contains the following fields, in order. Multi-byte integers use unsigned big-endian encoding. Offsets are measured from the start of the WebSocket message payload.

| Offset | Field | Size and meaning |
| --- | --- | --- |
| 0 | `real_len` | 2 bytes. Combined size of nonce, tag, and ciphertext. |
| 2 | `pad_len` | 2 bytes. Number of trailing padding bytes, from 0 through 256. |
| 4 | Nonce | 12 fresh random bytes per record. |
| 16 | GCM tag | 16 bytes. |
| 32 | Ciphertext | `real_len - 28` bytes. Decrypts to the command, stream ID, and application data. |
| `4 + real_len` | Padding | `pad_len` random bytes. The decoder skips their contents. |

The first four bytes, exactly as transmitted, are GCM additional authenticated data. The total message size must equal `4 + real_len + pad_len`. The decrypted record begins with a one-byte command and a four-byte nonzero stream ID, followed by 0 to 16,384 bytes of application data. Only `DATA` may carry application data. An invalid length, failed authentication, unknown command, zero stream ID, or payload on a control command ends the agent's WebSocket session.

For example, `04 00 00 00 07 61 62 63` is the plaintext for `DATA` on stream 7 carrying the three bytes `abc`. With zero padding, its outer header is `00 24 00 00` and the complete binary message is 40 bytes.

## Stream lifecycle

| Code | Command | Direction and effect |
| --- | --- | --- |
| 1 | `OPEN` | Receiver to Sender. The Receiver allocates a stream ID and requests a connection to the Sender's configured target. |
| 2 | `OPEN_OK` | Sender to Receiver. The target connection is ready. |
| 3 | `OPEN_FAIL` | Sender to Receiver. The requested stream could not be established. |
| 4 | `DATA` | Either direction after open. Append bytes to that direction's TCP stream in arrival order. |
| 5 | `CLOSE` | Either direction. Abort this stream and stop forwarding its data. |
| 6 | `EOF` | Either direction. Finish writing all preceding data to the local socket, then half-close its write side. The opposite direction may continue sending. |

For example, a Receiver may send `DATA` followed by `EOF` when an application finishes a request. The Sender can still return a response as `DATA` followed by its own `EOF`. The stream completes when both directions have ended and queued bytes have drained.

The reference agent also uses `CLOSE` for a stalled local consumer. It buffers up to 1 MiB per stream and resets the affected stream if the next frame cannot fit or its worker makes no local write progress for 15 seconds with data pending. These are local resource limits. Peers need only implement the wire-level `CLOSE` behavior.

## Obfuscation and observable metadata

The HTTP upgrade carries ordinary WebSocket metadata and can include a configured User-Agent, cookie, and subprotocol. The HTTP layer can return an ordinary JSON response to requests that do not establish a WebSocket. Such a response does not indicate that a peer has paired or a target service is healthy. After upgrade, the registration resembles a subscription message. Its topic is descriptive metadata. The Hub pairs agents using the channel ID and role.

Random trailing padding varies the transmitted size of binary records. The reference encoder defaults to a maximum of 192 padding bytes. Each encoder selects its own limit, and every v1 decoder accepts up to 256. The padding length is authenticated. The padding bytes sit outside the GCM ciphertext and authentication tag coverage.

The Hub can see registration metadata, timing, direction, and both record lengths. In particular, it can determine the application byte count as `real_len - 33`, even with padding enabled. With WSS, a network observer outside the TLS endpoints can still observe timing, direction, and TLS traffic sizes. v1 uses a long-lived channel key and carries no end-to-end sequence number or replay check. An active relay can replay previously authenticated records. A Hub configured with a raw channel secret can also derive the encryption key.

The implementation is in [WebSocket transport](../src/ws.c), [control parsing](../src/control.c), [Hub pairing](../src/hub.c), [record encoding](../src/crypto.c), and [stream dispatch](../src/agent.c). The [core tests](../tests/test_core.c) exercise record validation, pairing, and stream behavior.

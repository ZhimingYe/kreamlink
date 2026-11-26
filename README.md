# kreamlink

kreamlink gives a local application a fixed TCP address for reaching a remote service. For example, a writer can open a documentation preview at the same address in their browser while a build machine serves the latest draft. kreamlink runs on Linux and macOS.

The same binary runs all three roles.

| Mode | What it does |
| --- | --- |
| Receiver (`recv`) | Listens on the application's machine and keeps the local port bound while the Receiver is running, including during Hub or Sender outages. |
| Hub (`hub`) | Pairs the two agents by channel and relays their encrypted traffic. Both agents connect out to the Hub. |
| Sender (`send`) | Connects to the target service when a local application opens a connection through the Receiver. |

Multiple TCP connections share the tunnel. Each supports TCP half-close, so a client can finish sending a request and still read the reply. A local application that stops reading its stream can have that stream reset while others continue. If the Hub connection goes down, the agents reconnect automatically. Applications can open new connections once the agents pair again. Existing connections end with the old session.

## Build

Install a C11 compiler, Make, and the OpenSSL development libraries (`libssl-dev` or `openssl-devel` on Linux, `openssl@3` with Homebrew on macOS). Build from the repository root with Make.

```sh
make
```

To build with CMake instead, run `cmake -S . -B build && cmake --build build`.

## Try it locally with a documentation preview

Start a preview server on port 8000 with Python 3. It serves a single page from a temporary directory.

```sh
preview_dir=$(mktemp -d)
printf '%s\n' '<h1>Documentation preview</h1>' > "$preview_dir/index.html"
python3 -m http.server 8000 --bind 127.0.0.1 --directory "$preview_dir"
```

For this single-user loopback demo, choose a disposable Hub password and set `KREAMLINK_HUB_PASSWORD` to it in all three terminals. In the two agent terminals, also set `KREAMLINK_CHANNEL` to a second shared secret. Use the [hidden-input Bash commands](docs/credentials.md#environment-variables) to keep both values out of shell history and process arguments. From the repository root, run one command per terminal.

```sh
./kreamlink hub -l 127.0.0.1:8080
./kreamlink recv --insecure -u ws://127.0.0.1:8080/api/v1/stream -l 127.0.0.1:18080
./kreamlink send --insecure -u ws://127.0.0.1:8080/api/v1/stream -t 127.0.0.1:8000
```

Open `http://127.0.0.1:18080/` in your browser. The Receiver forwards the request through the tunnel to the preview server, and the page displays **Documentation preview**.

## Run across machines

Use your service manager's secret injection to set the environment variables. For file-based deployments, place each secret in a separate tenant-owned file with mode `0600` or `0400` and put its path in YAML. See [credentials on shared hosts](docs/credentials.md) for rootless setup and permissions. Either agent can register first. The Hub checks the password before creating a channel, joining it, or replacing a peer. Anyone with the Hub password can register on channels permitted by its allowlist.

Set both agents to the same reachable `wss://` Hub URL and the same high-entropy channel secret. Set the Receiver's listen address on the application machine and the Sender's target address as seen from the Sender. Each role accepts a configuration file, for example `./kreamlink -c examples/agent-recv.yaml`. See the [Hub](examples/hub.yaml), [Receiver](examples/agent-recv.yaml), and [Sender](examples/agent-send.yaml) examples.

Agents require verified WSS by default, including on shared machines. Only the explicit `--insecure` test option permits plain WS or unverified WSS on a numeric loopback address. When upgrading an existing installation, update the Hub and both agents together and configure the password on all three.

Use your existing HTTPS endpoint for the public WSS URL. The Hub accepts a standard HTTP/1.1 WebSocket upgrade on its configured path and checks the registration password after the upgrade. HTTPS termination belongs to the deployment. Direct TLS is also available with `--tls-cert` and `--tls-key`. The agents use the channel secret for end-to-end encryption. If the Hub restricts pairing with `allowed_tokens`, use derived channel IDs to keep the secret off the Hub. Protocol v1 allows an active relay to replay previously authenticated frames.

For wire formats and interoperability, see the [v1 protocol specification](docs/protocol-v1.md). For repository layout, implementation guidance, and tests, see [AGENTS.md](AGENTS.md).

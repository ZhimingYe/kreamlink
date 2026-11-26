#!/usr/bin/env bash
set -euo pipefail
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bin=${1:-./kreamlink}
core=${2:-./tests/test_core}
unset KREAMLINK_HUB_PASSWORD KREAMLINK_CHANNEL
umask 077
printf 'test-password\n' > "$tmp/password"
printf 'test-channel\r\n' > "$tmp/channel"
chmod 400 "$tmp/channel"
cat > "$tmp/private.yaml" <<CONF
mode: send
hub_password_file: "$tmp/password"
channel_file: "$tmp/channel"
hub: ws://192.0.2.1:8080/
target: 127.0.0.1:1
CONF

# Valid credentials reach the transport check, which exits before opening a socket.
expect_error() {
    local match=$1
    shift
    if "$@" 2>"$tmp/error"; then exit 1; fi
    grep -Fq "$match" "$tmp/error"
}
expect_error 'verified WSS' "$bin" -c "$tmp/private.yaml"
expect_error KREAMLINK_HUB_PASSWORD "$bin" hub -l invalid
expect_error 'verified WSS' "$bin" -c "$tmp/private.yaml" -u ws://127.0.0.1:8080/
expect_error 'verified WSS' "$bin" -c "$tmp/private.yaml" --insecure -u wss://192.0.2.1:8080/
KREAMLINK_HUB_PASSWORD= expect_error KREAMLINK_HUB_PASSWORD "$bin" -c "$tmp/private.yaml"
chmod 644 "$tmp/password"
expect_error KREAMLINK_HUB_PASSWORD "$bin" -c "$tmp/private.yaml"
KREAMLINK_HUB_PASSWORD=test-env expect_error 'verified WSS' "$bin" -c "$tmp/private.yaml"
chmod 600 "$tmp/password"
chmod 640 "$tmp/channel"
expect_error KREAMLINK_CHANNEL "$bin" -c "$tmp/private.yaml"
KREAMLINK_CHANNEL=test-env expect_error 'verified WSS' "$bin" -c "$tmp/private.yaml"
chmod 400 "$tmp/channel"
mv "$tmp/password" "$tmp/real"
ln -s "$tmp/real" "$tmp/password"
expect_error KREAMLINK_HUB_PASSWORD "$bin" -c "$tmp/private.yaml"
rm "$tmp/password"
mkfifo "$tmp/password"
expect_error KREAMLINK_HUB_PASSWORD "$bin" -c "$tmp/private.yaml"
rm "$tmp/password"
for content in '' 'one\ntwo' 'abc\0extra'; do
    printf '%b' "$content" > "$tmp/password"
    expect_error KREAMLINK_HUB_PASSWORD "$bin" -c "$tmp/private.yaml"
done
printf '%0255d\r\n' 0 > "$tmp/password"
expect_error 'verified WSS' "$bin" -c "$tmp/private.yaml"
printf '%0256d' 0 > "$tmp/password"
expect_error KREAMLINK_HUB_PASSWORD "$bin" -c "$tmp/private.yaml"
for config in examples/*.yaml; do "$bin" -c "$config" -h 2>/dev/null; done

for bad in 'hub_password: inline' 'allowed_tokens: []' 'allowed_tokens:' 'allowed_token: secret' 'heartbeat: 1s' 'insecure: perhaps'; do
    printf '%s\n' "$bad" > "$tmp/config"
    if "$bin" -c "$tmp/config" -h 2>/dev/null; then exit 1; fi
done
for bad in 0 -1 9999999999999999999 12s; do
    if "$bin" --heartbeat "$bad" -h 2>/dev/null; then exit 1; fi
done
printf 'allowed_tokens:\n  - "test#channel"\n' > "$tmp/config"
"$bin" -c "$tmp/config" -h 2>/dev/null

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -config tests/test_cert.cnf \
    -keyout "$tmp/key.pem" -out "$tmp/cert.pem" 2>/dev/null
SSL_CERT_FILE="$tmp/cert.pem" "$core" "$tmp/cert.pem" "$tmp/key.pem"

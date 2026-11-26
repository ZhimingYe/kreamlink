#!/usr/bin/env bash
set -euo pipefail
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bin=${1:-./kreamlink}
core=${2:-./tests/test_core}
for config in examples/*.yaml; do "$bin" -c "$config" -h 2>/dev/null; done

for bad in 'allowed_tokens: []' 'allowed_tokens:' 'allowed_token: secret' 'heartbeat: 1s' 'insecure: perhaps'; do
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

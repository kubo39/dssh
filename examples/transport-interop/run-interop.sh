#!/usr/bin/env bash
#
# Interop test: connect to a throwaway OpenSSH server (in Docker) and verify the full
# handshake + host key verification (known_hosts) + Ed25519 publickey authentication + exec.
#
# Security: the sshd binds to 127.0.0.1 only (never reachable from the network), runs as a
# non-root user in an ephemeral (--rm) container with password auth disabled, uses a
# throwaway host/client key, and is torn down on exit. Nothing on the host is modified.
#
# Requires: docker, ssh-keygen, dub/ldc2.
# Usage: ./run-interop.sh [port]   (default port 2022)

set -euo pipefail

PORT="${1:-2022}"
CONTAINER=dssh-interop
WORKDIR="$(cd "$(dirname "$0")" && pwd)"
KEYDIR="$(mktemp -d)"
KEY="$KEYDIR/id_ed25519"

cleanup() {
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$KEYDIR"
}
trap cleanup EXIT

# Throwaway client key.
ssh-keygen -t ed25519 -N "" -C "dssh-interop" -f "$KEY" >/dev/null

dub build --root="$WORKDIR" >/dev/null

# Loopback-only, ephemeral sshd with our public key authorized for an unlocked user.
docker run -d --rm --name "$CONTAINER" -p "127.0.0.1:${PORT}:22" \
    -e PUBKEY="$(cat "$KEY.pub")" \
    alpine sh -c '
        apk add --no-cache openssh-server >/dev/null 2>&1 &&
        ssh-keygen -A &&
        adduser -D tester &&
        echo "tester:unused-$(head -c12 /dev/urandom | base64)" | chpasswd &&
        mkdir -p /home/tester/.ssh &&
        echo "$PUBKEY" > /home/tester/.ssh/authorized_keys &&
        chmod 700 /home/tester/.ssh && chmod 600 /home/tester/.ssh/authorized_keys &&
        chown -R tester /home/tester/.ssh &&
        exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no' >/dev/null

echo "waiting for sshd (loopback 127.0.0.1:${PORT}, ephemeral)..."
for _ in $(seq 1 90); do
    docker logs "$CONTAINER" 2>&1 | grep -q "Server listening" && break
    sleep 1
done

# Pin the server's ed25519 host key so the client verifies it via knownHosts() — this also
# exercises the known_hosts parser against a real OpenSSH-generated host key. A non-default
# port uses the [host]:port form.
KNOWN_HOSTS="$KEYDIR/known_hosts"
HOSTKEY="$(docker exec "$CONTAINER" cat /etc/ssh/ssh_host_ed25519_key.pub | cut -d' ' -f1-2)"
echo "[127.0.0.1]:${PORT} ${HOSTKEY}" > "$KNOWN_HOSTS"

"$WORKDIR/transport-interop" "$PORT" tester "$KEY" "$KNOWN_HOSTS"

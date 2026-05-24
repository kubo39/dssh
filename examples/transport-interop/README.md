# transport-interop

Connects to a real OpenSSH server with `dssh:vibe` and verifies that the
**transport handshake → host key verification (`known_hosts`) → publickey authentication →
remote `exec`** interoperate.

## Run

```
./run-interop.sh          # port 2022 (default)
./run-interop.sh 2222     # custom port
```

`run-interop.sh`:
1. generates a throwaway ed25519 client key
2. builds the client
3. starts an OpenSSH sshd in Docker (with the public key in `authorized_keys`)
4. pins the server's ed25519 host key into a `known_hosts` file (`[127.0.0.1]:port` form)
5. runs the client (connect → KEX → **host key verified against `known_hosts`** → publickey auth → verify `echo` output)
6. tears everything down

On success it prints `OK: known_hosts-verified transport + publickey auth + exec ...` and exits 0.
The host key step doubles as a real-OpenSSH test of `knownHosts()`.

## Security

The test sshd binds to **`127.0.0.1` only** (unreachable from the network), runs as a
non-root user in an ephemeral (`--rm`) container with password auth disabled. The host and
client keys are throwaway and removed on exit. Nothing on the host is modified.

## Requirements

docker, ssh-keygen, dub/ldc2.

## Known limitations (MVP)

- Run without a `known_hosts` argument, the client falls back to `insecureAcceptAll` (test only).
- Only `run()` (collects all output); streaming `exec` is not implemented yet.

# dssh

[![CI](https://github.com/kubo39/dssh/actions/workflows/ci.yml/badge.svg)](https://github.com/kubo39/dssh/actions/workflows/ci.yml)

A pure D SSH-2.0 client library.

> ⚠️ **Experimental — not for production.** A hobby/learning implementation of the SSH-2.0
> protocol. It has **not been security-audited**; do not use it to protect real credentials
> or data. Cryptographic primitives are delegated to OpenSSL (see [Cryptography](#cryptography)),
> but the protocol layer, key handling, and host-key verification are unreviewed.

## Layout (two dub packages, sans-I/O two-layer design)

| dub package | import root | contents |
|---|---|---|
| `dssh` (core) | `dssh` | protocol state machine, wire format, KEX / cipher / auth logic. **vibe-core-independent** (sans-I/O) |
| `dssh:vibe` (adapter) | `dssh.vibe` | `connectSSH` / `SshClient` / `SshChannel`, TCP + Fiber pump |

```d
import dssh.vibe;

void main() {
    runApplication({
        auto sess = connectSSH("host", 22, SshConfig(hostKeyVerifier: knownHosts()));
        scope (exit) sess.close();
        sess.authenticate("alice", [ publicKey(loadPrivateKey("~/.ssh/id_ed25519")) ]);
        auto r = sess.run("uname -a");
        // r.stdout, r.stderr, r.status.code
    });
}
```

## Build

```
dub build         # core (dssh)
dub build :vibe   # adapter (dssh.vibe)
dub test          # unit tests
```

## Cryptography

All cryptographic primitives are **delegated to an audited C library (OpenSSL)** via FFI
(dub package `openssl`, the deimos bindings). No pure-D crypto implementation is used.

## Interop

[`examples/transport-interop`](examples/transport-interop) connects to a throwaway OpenSSH
server in Docker and verifies the full handshake + host key verification (`known_hosts`)
+ Ed25519 publickey auth + remote exec:

```
cd examples/transport-interop && ./run-interop.sh
```

## Status

Experimental. Working today, all interoperating with real OpenSSH:

- transport handshake: `curve25519-sha256`, `ssh-ed25519` host keys, `aes256-gcm@openssh.com`
- host key verification: `knownHosts()` (plain / `[host]:port` / hashed), `acceptFingerprint()`
- Ed25519 publickey authentication
- encrypted private keys: `aes256-ctr` + `bcrypt-pbkdf`. The passphrase is interpreted as
  its UTF-8 byte representation; a passphrase set with a different byte encoding will not
  decrypt the key.
- remote command execution: buffered `run()` and streaming `exec()` (stdin via `write`,
  incremental `read`/`readStderr`, `waitExit`) over a background pump fiber
- interactive shell with a pseudo-terminal: `shell()` (+ `windowChange()`)
- rekey: server-initiated and client-initiated (byte threshold)

Not yet implemented: SFTP, port forwarding, password &
keyboard-interactive auth, RSA / ECDSA host keys,
`chacha20-poly1305@openssh.com`, time-based rekey, server side.

/// Transport-layer state machine (RFC 4253).
module dssh.transport;

import std.sumtype : SumType;
import dssh.messages : KexInit, KexEcdhInit, KexEcdhReply, NewKeys;
import dssh.exception : SshProtocolException;
import dssh.wire : SshBuffer;
import dssh.crypto.openssl : sha256, x25519, x25519Generate, X25519KeyPair, ed25519Verify;
import dssh.secret : secureZero;

struct VersionExchange {} // awaiting server banner
struct Kex {}             // KEXINIT/ECDH in progress (initial or rekey)
struct AwaitingNewKeys {} // our NEWKEYS sent, awaiting peer's (renamed to avoid the NewKeys message)
struct Established {}      // transport up

alias TransportState = SumType!(VersionExchange, Kex, AwaitingNewKeys, Established);

/// Algorithms chosen by KEXINIT negotiation (RFC 4253 §7.1).
struct Negotiated
{
    string kex;
    string hostKey;
    string cipherC2S;
    string cipherS2C;
    string macC2S;
    string macS2C;
    string compressionC2S;
    string compressionS2C;
}

/// Choose algorithms from the two KEXINIT lists, or throw if any has no overlap.
Negotiated negotiate(in KexInit client, in KexInit server) @safe
{
    Negotiated n;
    n.kex = pick(client.kex, server.kex, "kex algorithm");
    n.hostKey = pick(client.serverHostKey, server.serverHostKey, "host key algorithm");
    n.cipherC2S = pick(client.encryptionC2S, server.encryptionC2S, "client-to-server cipher");
    n.cipherS2C = pick(client.encryptionS2C, server.encryptionS2C, "server-to-client cipher");
    n.macC2S = isAead(n.cipherC2S) ? "" : pick(client.macC2S, server.macC2S, "client-to-server MAC");
    n.macS2C = isAead(n.cipherS2C) ? "" : pick(client.macS2C, server.macS2C, "server-to-client MAC");
    n.compressionC2S = pick(client.compressionC2S, server.compressionC2S, "client-to-server compression");
    n.compressionS2C = pick(client.compressionS2C, server.compressionS2C, "server-to-client compression");
    return n;
}

private string pick(const(string)[] client, const(string)[] server, string what) @safe
{
    import std.algorithm.searching : canFind;

    foreach (c; client)
        if (server.canFind(c))
            return c;
    throw new SshProtocolException("no common " ~ what);
}

/// AEAD ciphers carry integrity themselves, so no separate MAC is negotiated.
private bool isAead(string cipher) @safe pure nothrow
{
    return cipher == "aes128-gcm@openssh.com"
        || cipher == "aes256-gcm@openssh.com"
        || cipher == "chacha20-poly1305@openssh.com";
}

@safe unittest
{
    KexInit c;
    c.kex = ["curve25519-sha256", "ecdh-sha2-nistp256"];
    c.serverHostKey = ["ssh-ed25519"];
    c.encryptionC2S = ["aes256-ctr"];
    c.encryptionS2C = ["aes256-ctr"];
    c.macC2S = ["hmac-sha2-256"];
    c.macS2C = ["hmac-sha2-256"];
    c.compressionC2S = ["none"];
    c.compressionS2C = ["none"];

    KexInit s;
    s.kex = ["ecdh-sha2-nistp256", "curve25519-sha256"];
    s.serverHostKey = ["rsa-sha2-256", "ssh-ed25519"];
    s.encryptionC2S = ["aes256-ctr", "aes128-ctr"];
    s.encryptionS2C = ["aes256-ctr"];
    s.macC2S = ["hmac-sha2-256"];
    s.macS2C = ["hmac-sha2-256"];
    s.compressionC2S = ["none"];
    s.compressionS2C = ["none"];

    auto n = negotiate(c, s);
    assert(n.kex == "curve25519-sha256"); // first client algo also in server
    assert(n.hostKey == "ssh-ed25519");
    assert(n.cipherC2S == "aes256-ctr");
    assert(n.cipherS2C == "aes256-ctr");
    assert(n.macC2S == "hmac-sha2-256");
    assert(n.macS2C == "hmac-sha2-256");
    assert(n.compressionC2S == "none");
    assert(n.compressionS2C == "none");
}

@safe unittest // AEAD cipher: MAC is implicit, empty MAC lists are valid
{
    KexInit c, s;
    c.kex = s.kex = ["curve25519-sha256"];
    c.serverHostKey = s.serverHostKey = ["ssh-ed25519"];
    c.encryptionC2S = c.encryptionS2C = ["aes256-gcm@openssh.com"];
    s.encryptionC2S = s.encryptionS2C = ["aes256-gcm@openssh.com"];
    c.compressionC2S = c.compressionS2C = ["none"];
    s.compressionC2S = s.compressionS2C = ["none"];

    auto n = negotiate(c, s);
    assert(n.cipherC2S == "aes256-gcm@openssh.com");
    assert(n.macC2S == "");
    assert(n.macS2C == "");
}

@safe unittest // no overlapping kex algorithm is a protocol failure
{
    import std.exception : assertThrown;

    KexInit c, s;
    c.kex = ["curve25519-sha256"];
    s.kex = ["diffie-hellman-group14-sha256"];
    assertThrown!SshProtocolException(negotiate(c, s));
}

/**
 * KEX exchange hash H (RFC 5656 §4 / RFC 8731): each of V_C..Q_S as an SSH `string`,
 * the shared secret K as `mpint`, all hashed with SHA-256.
 */
ubyte[32] exchangeHash(const(ubyte)[] clientVersion, const(ubyte)[] serverVersion,
                       const(ubyte)[] clientKexInit, const(ubyte)[] serverKexInit,
                       const(ubyte)[] hostKey, const(ubyte)[] clientEphemeral,
                       const(ubyte)[] serverEphemeral, const(ubyte)[] sharedSecret)
{
    SshBuffer b;
    b.putString(clientVersion);
    b.putString(serverVersion);
    b.putString(clientKexInit);
    b.putString(serverKexInit);
    b.putString(hostKey);
    b.putString(clientEphemeral);
    b.putString(serverEphemeral);
    b.putMpint(sharedSecret);
    return sha256(b.data);
}

unittest // exchange hash assembles fields in RFC 5656/8731 order and encoding
{
    ubyte[] vc = [0x10];
    ubyte[] vs = [0x20];
    ubyte[] ic = [0x30, 0x31];
    ubyte[] iss = [0x40];
    ubyte[] ks = [0x50];
    ubyte[] qc = [0x60];
    ubyte[] qs = [0x70];
    ubyte[] k = [0x01, 0x02];

    SshBuffer hashInput;
    hashInput.putString(vc);
    hashInput.putString(vs);
    hashInput.putString(ic);
    hashInput.putString(iss);
    hashInput.putString(ks);
    hashInput.putString(qc);
    hashInput.putString(qs);
    hashInput.putMpint(k);
    ubyte[32] expected = sha256(hashInput.data);

    assert(exchangeHash(vc, vs, ic, iss, ks, qc, qs, k) == expected);
}

/**
 * Derive a key of `length` bytes from the shared secret and exchange hash (RFC 4253 §7.2).
 * `letter` selects which key ('A'..'F'); `sessionId` is H of the first KEX.
 */
ubyte[] deriveKey(const(ubyte)[] sharedSecret, const(ubyte)[] exchangeHashH,
                  const(ubyte)[] sessionId, char letter, size_t length)
{
    SshBuffer b;
    b.putMpint(sharedSecret);
    b.putRaw(exchangeHashH);
    b.putByte(cast(ubyte) letter);
    b.putRaw(sessionId);
    ubyte[32] block = sha256(b.data);
    ubyte[] result = block.dup;

    while (result.length < length)
    {
        SshBuffer e;
        e.putMpint(sharedSecret);
        e.putRaw(exchangeHashH);
        e.putRaw(result);
        ubyte[32] next = sha256(e.data);
        result ~= next[];
    }
    return result[0 .. length];
}

unittest // K1 = HASH(mpint(K) || H || letter || session_id), truncated
{
    ubyte[] k = [0x01, 0x02, 0x03];
    ubyte[32] h;
    foreach (i; 0 .. 32) h[i] = cast(ubyte)(i + 1);
    ubyte[32] sid;
    foreach (i; 0 .. 32) sid[i] = cast(ubyte)(0x80 + i);

    SshBuffer hashInput;
    hashInput.putMpint(k);
    hashInput.putRaw(h[]);
    hashInput.putByte(cast(ubyte) 'A');
    hashInput.putRaw(sid[]);
    ubyte[32] k1 = sha256(hashInput.data);

    auto key = deriveKey(k, h[], sid[], 'A', 16);
    assert(key.length == 16);
    assert(key == k1[0 .. 16]);
}

unittest // keys longer than the hash are extended: K2 = HASH(mpint(K) || H || K1)
{
    ubyte[] k = [0x09];
    ubyte[32] h = 0;
    ubyte[32] sid = 0;

    SshBuffer b1;
    b1.putMpint(k);
    b1.putRaw(h[]);
    b1.putByte(cast(ubyte) 'C');
    b1.putRaw(sid[]);
    ubyte[32] k1 = sha256(b1.data);

    SshBuffer b2;
    b2.putMpint(k);
    b2.putRaw(h[]);
    b2.putRaw(k1[]);
    ubyte[32] k2 = sha256(b2.data);

    auto key = deriveKey(k, h[], sid[], 'C', 48);
    assert(key.length == 48);
    assert(key[0 .. 32] == k1[]);
    assert(key[32 .. 48] == k2[0 .. 16]);
}

/// Derived session keys (AES-256-GCM: 32-byte keys, 12-byte initial IVs). MAC keys are
/// unused for AEAD. sessionId = H of the first KEX.
struct KexResult
{
    ubyte[32] sessionId;
    ubyte[] ivClientToServer;
    ubyte[] ivServerToClient;
    ubyte[] encKeyClientToServer;
    ubyte[] encKeyServerToClient;
}

/// Client-side curve25519-sha256 + ssh-ed25519 KEX driver (sans-I/O).
struct ClientKex
{
    private const(ubyte)[] vC;
    private const(ubyte)[] vS;
    private const(ubyte)[] iC;
    private KexInit clientKexInit;
    private const(ubyte)[] iS;
    private Negotiated negotiated_;
    private X25519KeyPair ephemeral;
    private bool established_;
    private KexResult result_;
    private const(ubyte)[] priorSessionId; // set on rekey; the first KEX uses its own H

    @disable this(this); // holds the ephemeral private key and derived session keys

    // Scrub key material on destruction (deterministic via ProtocolCore.~this on close()).
    ~this() @nogc nothrow
    {
        secureZero(result_.encKeyClientToServer);
        secureZero(result_.encKeyServerToClient);
        secureZero(ephemeral.privateKey[]);
    }

    this(const(ubyte)[] clientVersion, const(ubyte)[] serverVersion,
         KexInit clientKexInit, const(ubyte)[] clientKexInitBytes,
         const(ubyte)[] priorSessionId = null)
    {
        vC = clientVersion;
        vS = serverVersion;
        this.clientKexInit = clientKexInit;
        iC = clientKexInitBytes;
        this.priorSessionId = priorSessionId;
    }

    /// On the server KEXINIT: negotiate, generate the ephemeral key, return KEX_ECDH_INIT.
    /// Throws SshProtocolException if negotiation picks an algorithm this driver cannot run.
    KexEcdhInit onServerKexInit(in KexInit serverKexInit, const(ubyte)[] serverKexInitBytes)
    {
        negotiated_ = negotiate(clientKexInit, serverKexInit);
        requireSupported(negotiated_);
        iS = serverKexInitBytes;
        ephemeral = x25519Generate();
        return KexEcdhInit(ephemeral.publicKey[]);
    }

    /// On KEX_ECDH_REPLY: derive K and H, verify the host-key signature, derive keys,
    /// return NEW_KEYS. Throws SshProtocolException on signature failure.
    NewKeys onKexEcdhReply(in KexEcdhReply reply)
    {
        auto k = x25519(ephemeral.privateKey[], reply.serverPublicKey);
        auto h = exchangeHash(vC, vS, iC, iS, reply.hostKey,
                              ephemeral.publicKey[], reply.serverPublicKey, k[]);

        const hostPub = unwrapEd25519(reply.hostKey, "ssh-ed25519");
        const sig = unwrapEd25519(reply.signature, "ssh-ed25519");
        if (!ed25519Verify(hostPub, h[], sig))
            throw new SshProtocolException("host key signature verification failed");

        // First KEX: session id = H. Rekey: keep the original session id for derivation.
        const(ubyte)[] sid = priorSessionId.length ? priorSessionId : h[];
        result_.sessionId = h;
        result_.ivClientToServer = deriveKey(k[], h[], sid, 'A', 12);
        result_.ivServerToClient = deriveKey(k[], h[], sid, 'B', 12);
        result_.encKeyClientToServer = deriveKey(k[], h[], sid, 'C', 32);
        result_.encKeyServerToClient = deriveKey(k[], h[], sid, 'D', 32);

        // K and the ephemeral private key are no longer needed; scrub them now.
        secureZero(k[]);
        secureZero(ephemeral.privateKey[]);
        return NewKeys();
    }

    /// On the server NEW_KEYS: handshake complete.
    void onNewKeys() { established_ = true; }

    bool established() const { return established_; }
    Negotiated negotiated() const { return negotiated_; }
    KexResult result() { return result_; }
}

// The config's algorithm lists are user-extendable, so negotiation can land on names this
// driver does not implement; fail loudly here rather than installing the wrong cipher.
private void requireSupported(in Negotiated n) @safe
{
    static void require(string got, string supported, string what) @safe
    {
        if (got != supported)
            throw new SshProtocolException("negotiated unsupported " ~ what ~ ": " ~ got);
    }

    require(n.kex, "curve25519-sha256", "kex algorithm");
    require(n.hostKey, "ssh-ed25519", "host key algorithm");
    require(n.cipherC2S, "aes256-gcm@openssh.com", "client-to-server cipher");
    require(n.cipherS2C, "aes256-gcm@openssh.com", "server-to-client cipher");
    require(n.compressionC2S, "none", "client-to-server compression");
    require(n.compressionS2C, "none", "server-to-client compression");
}

// Extract the raw key/signature from an SSH ed25519 blob: string(type) || string(bytes).
private const(ubyte)[] unwrapEd25519(const(ubyte)[] blob, string expectedType)
{
    auto b = SshBuffer(blob);
    if (b.readStr() != expectedType)
        throw new SshProtocolException("unexpected ssh-ed25519 blob type");
    return b.readString();
}

unittest // full client KEX against a simulated server: both sides derive the same keys
{
    import dssh.crypto.openssl : ed25519Generate, ed25519Sign;

    const(ubyte)[] vc = cast(const(ubyte)[]) "SSH-2.0-client";
    const(ubyte)[] vs = cast(const(ubyte)[]) "SSH-2.0-server";

    KexInit cki;
    cki.kex = ["curve25519-sha256"];
    cki.serverHostKey = ["ssh-ed25519"];
    cki.encryptionC2S = ["aes256-gcm@openssh.com"];
    cki.encryptionS2C = ["aes256-gcm@openssh.com"];
    cki.compressionC2S = ["none"];
    cki.compressionS2C = ["none"];

    SshBuffer cb;
    cki.serialize(cb);
    const(ubyte)[] iC = cb.data;

    KexInit ski = cki;
    SshBuffer sbuf;
    ski.serialize(sbuf);
    const(ubyte)[] iS = sbuf.data;

    auto hostKey = ed25519Generate();
    auto serverEph = x25519Generate();

    auto kex = ClientKex(vc, vs, cki, iC);
    auto ecdhInit = kex.onServerKexInit(ski, iS);
    const(ubyte)[] qc = ecdhInit.clientPublicKey;

    // server computes K, H and signs H with the host key
    const(ubyte)[] qs = serverEph.publicKey[];
    auto kServer = x25519(serverEph.privateKey[], qc);
    SshBuffer ksb;
    ksb.putStr("ssh-ed25519");
    ksb.putString(hostKey.publicKey[]);
    const(ubyte)[] ksBlob = ksb.data;
    auto hServer = exchangeHash(vc, vs, iC, iS, ksBlob, qc, qs, kServer[]);
    auto sigRaw = ed25519Sign(hostKey.privateKey[], hServer[]);
    SshBuffer sigb;
    sigb.putStr("ssh-ed25519");
    sigb.putString(sigRaw[]);

    auto reply = KexEcdhReply(ksBlob, qs, sigb.data);
    kex.onKexEcdhReply(reply);
    kex.onNewKeys();

    assert(kex.established());
    auto r = kex.result();
    assert(r.sessionId == hServer);
    assert(r.ivClientToServer == deriveKey(kServer[], hServer[], hServer[], 'A', 12));
    assert(r.encKeyClientToServer == deriveKey(kServer[], hServer[], hServer[], 'C', 32));
    assert(r.ivClientToServer.length == 12);
    assert(r.encKeyClientToServer.length == 32);
}

unittest // negotiating an algorithm we cannot run must fail, not silently use AES-GCM
{
    import std.exception : assertThrown;

    KexInit cki;
    cki.kex = ["curve25519-sha256"];
    cki.serverHostKey = ["ssh-ed25519"];
    cki.encryptionC2S = ["aes256-ctr"]; // negotiable, but ProtocolCore only implements GCM
    cki.encryptionS2C = ["aes256-ctr"];
    cki.macC2S = ["hmac-sha2-256"];
    cki.macS2C = ["hmac-sha2-256"];
    cki.compressionC2S = ["none"];
    cki.compressionS2C = ["none"];
    KexInit ski = cki;

    auto kex = ClientKex(cast(const(ubyte)[]) "SSH-2.0-c", cast(const(ubyte)[]) "SSH-2.0-s",
                         cki, [ubyte(1)]);
    assertThrown!SshProtocolException(kex.onServerKexInit(ski, [ubyte(2)]));
}

unittest // KEX rejects an invalid host-key signature
{
    import dssh.crypto.openssl : ed25519Generate;
    import std.exception : assertThrown;

    const(ubyte)[] vc = cast(const(ubyte)[]) "SSH-2.0-c";
    const(ubyte)[] vs = cast(const(ubyte)[]) "SSH-2.0-s";

    KexInit cki;
    cki.kex = ["curve25519-sha256"];
    cki.serverHostKey = ["ssh-ed25519"];
    cki.encryptionC2S = ["aes256-gcm@openssh.com"];
    cki.encryptionS2C = ["aes256-gcm@openssh.com"];
    cki.compressionC2S = ["none"];
    cki.compressionS2C = ["none"];
    SshBuffer cb;
    cki.serialize(cb);
    KexInit ski = cki;
    SshBuffer sbuf;
    ski.serialize(sbuf);

    auto hostKey = ed25519Generate();
    auto serverEph = x25519Generate();

    auto kex = ClientKex(vc, vs, cki, cb.data);
    kex.onServerKexInit(ski, sbuf.data);

    SshBuffer ksb;
    ksb.putStr("ssh-ed25519");
    ksb.putString(hostKey.publicKey[]);
    SshBuffer sigb;
    sigb.putStr("ssh-ed25519");
    sigb.putString(new ubyte[64]); // all-zero signature
    auto reply = KexEcdhReply(ksb.data, serverEph.publicKey[], sigb.data);

    assertThrown!SshProtocolException(kex.onKexEcdhReply(reply));
}

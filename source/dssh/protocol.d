/// sans-I/O protocol core: feed bytes, take outgoing bytes + events.
///
/// Drives the transport handshake: banner exchange → plaintext KEXINIT/ECDH → KEX driver →
/// NEW_KEYS cipher switch. After that, incoming packets are decrypted and surfaced as events
/// for the (future) auth/connection layer.
module dssh.protocol;

import std.algorithm.searching : countUntil;
import dssh.config : SshConfig;
import dssh.exception : SshProtocolException, SshConnectException, SshHostKeyException;
import dssh.hostkey : HostKeyInfo, HostKeyDecision, KnownHostStatus;
import dssh.wire : SshBuffer;
import dssh.messages : SshMsg, KexInit, KexEcdhInit, KexEcdhReply, NewKeys;
import dssh.packet : PacketCipher, PlaintextCipher, AesGcmCipher;
import dssh.transport : ClientKex, TransportState, VersionExchange, Kex, AwaitingNewKeys, Established;
import dssh.crypto.openssl : randomBytes, sha256;
import std.sumtype : match;

struct ProtocolCore
{
    @disable this(this); // holds key material via ClientKex

    private SshConfig cfg;
    private string host;
    private ushort port;
    private const(ubyte)[] clientVersion;
    private const(ubyte)[] serverVersion;
    private ubyte[] inbuf;
    private ubyte[] outbuf;
    private PacketCipher rx;
    private PacketCipher tx;
    private TransportState state = TransportState(VersionExchange());
    private KexInit clientKexInit;
    private const(ubyte)[] clientKexInitBytes;
    private ClientKex kex;
    private ubyte[][] events;
    private ubyte[][] appOutQueue; // app packets buffered while a (re)key exchange is in flight
    private ulong bytesSinceKex;   // app bytes since the last completed KEX (client rekey trigger)
    private ubyte[] sessionId_;

    this(SshConfig cfg, string host = null, ushort port = 0)
    {
        this.cfg = cfg;
        this.host = host;
        this.port = port;
        clientVersion = cast(const(ubyte)[]) cfg.clientVersion;
        rx = new PlaintextCipher;
        tx = new PlaintextCipher;
    }

    // Destroying the ciphers scrubs the live session keys (AesGcmCipher.~this); the kex
    // member's ~this scrubs the derived keys. Triggered deterministically by close().
    ~this()
    {
        if (rx !is null)
            destroy(rx);
        if (tx !is null)
            destroy(tx);
    }

    /// Produce the client banner + KEXINIT. Call once at the start.
    void start()
    {
        outbuf ~= clientVersion;
        outbuf ~= cast(const(ubyte)[]) "\r\n";
        clientKexInit = makeClientKexInit();
        SshBuffer b;
        clientKexInit.serialize(b);
        clientKexInitBytes = b.data;
        outbuf ~= tx.encryptPacket(clientKexInitBytes);
    }

    /// Feed received bytes; processes complete banner/packets and advances the handshake.
    void feedIncoming(const(ubyte)[] bytes)
    {
        inbuf ~= bytes;
        for (;;)
        {
            if (awaitingBanner())
            {
                auto nl = inbuf.countUntil(cast(ubyte) '\n');
                if (nl < 0)
                    return;
                size_t end = nl;
                if (end > 0 && inbuf[end - 1] == '\r')
                    end--;
                serverVersion = inbuf[0 .. end].dup;
                inbuf = inbuf[nl + 1 .. $];
                state = TransportState(Kex());
                continue;
            }
            const lfSize = rx.lengthFieldSize();
            if (inbuf.length < lfSize)
                return;
            const total = lfSize + rx.trailingSize(inbuf[0 .. lfSize]);
            if (inbuf.length < total)
                return;
            auto payload = rx.decryptPacket(inbuf[0 .. total]);
            inbuf = inbuf[total .. $];
            dispatch(payload);
        }
    }

    /// Drain bytes to send.
    ubyte[] takeOutgoing()
    {
        auto o = outbuf;
        outbuf = null;
        return o;
    }

    /// Drain decrypted payloads received after the transport is established.
    ubyte[][] takeEvents()
    {
        auto e = events;
        events = null;
        return e;
    }

    bool transportEstablished() const { return sessionId_.length > 0; }

    /// Session identifier (H of the first KEX); used to sign publickey auth requests.
    const(ubyte)[] sessionId() const { return sessionId_; }

    /// Encrypt and queue an application packet (valid once the transport is established).
    void sendPacket(const(ubyte)[] payload)
    {
        // While our KEXINIT is out but our NEWKEYS isn't (state Kex), only KEX messages may
        // go on the wire (RFC 4253 §9); buffer app packets until the new keys are installed.
        if (inKeyExchange())
            appOutQueue ~= payload.dup;
        else
        {
            outbuf ~= tx.encryptPacket(payload);
            accountAndMaybeRekey(payload.length);
        }
    }

    private KexInit makeClientKexInit()
    {
        KexInit m;
        randomBytes(m.cookie[]);
        m.kex = cfg.algorithms.kex;
        m.serverHostKey = cfg.algorithms.hostKey;
        m.encryptionC2S = cfg.algorithms.cipher;
        m.encryptionS2C = cfg.algorithms.cipher;
        m.macC2S = cfg.algorithms.mac;
        m.macS2C = cfg.algorithms.mac;
        m.compressionC2S = cfg.algorithms.compression;
        m.compressionS2C = cfg.algorithms.compression;
        return m;
    }

    private bool awaitingBanner()
    {
        return state.match!((VersionExchange _) => true, _ => false);
    }

    private bool inKeyExchange()
    {
        return state.match!((Kex _) => true, _ => false);
    }

    private void dispatch(const(ubyte)[] payload)
    {
        if (payload.length == 0)
            return;
        const msg = cast(SshMsg) payload[0];
        state.match!(
            (VersionExchange _) { throw new SshProtocolException("packet before banner"); },
            (Kex _) => handleKex(msg, payload),
            (AwaitingNewKeys _) => handleAwaitingNewKeys(msg),
            (Established _) => handleEstablished(msg, payload),
        );
    }

    // Kex state: drive the KEX driver (our KEXINIT already sent by start/startRekey).
    private void handleKex(SshMsg msg, const(ubyte)[] payload)
    {
        switch (msg)
        {
        case SshMsg.kexInit:
            auto pb = SshBuffer(payload);
            auto serverKexInit = KexInit.parse(pb);
            kex = ClientKex(clientVersion, serverVersion, clientKexInit, clientKexInitBytes, sessionId_);
            SshBuffer ob;
            kex.onServerKexInit(serverKexInit, payload.dup).serialize(ob);
            outbuf ~= tx.encryptPacket(ob.data); // KEX_ECDH_INIT
            break;
        case SshMsg.kexEcdhReply:
            auto pb = SshBuffer(payload);
            auto reply = KexEcdhReply.parse(pb);
            auto newkeys = kex.onKexEcdhReply(reply); // ed25519 signature verification
            verifyHostKeyPolicy(reply.hostKey);       // trust-policy callback
            SshBuffer ob;
            newkeys.serialize(ob);
            outbuf ~= tx.encryptPacket(ob.data);      // our NEWKEYS (still on the old tx)
            auto r = kex.result();
            auto oldTx = tx;
            tx = new AesGcmCipher(r.encKeyClientToServer, r.ivClientToServer); // switch tx
            destroy(oldTx);                            // scrub the previous c2s key now
            flushAppOutQueue();                        // app data may flow again under the new tx
            state = TransportState(AwaitingNewKeys());
            break;
        default:
            // During a rekey the peer may still send in-flight app data before it sees our
            // KEXINIT (RFC 4253 §7.1); deliver it. Before the first KEX it is a violation.
            if (sessionId_.length > 0)
                events ~= payload.dup;
            else
                throw new SshProtocolException("unexpected message during key exchange");
            break;
        }
    }

    private void handleAwaitingNewKeys(SshMsg msg)
    {
        if (msg != SshMsg.newKeys)
            throw new SshProtocolException("expected NEWKEYS");
        auto r = kex.result();
        auto oldRx = rx;
        rx = new AesGcmCipher(r.encKeyServerToClient, r.ivServerToClient); // switch rx
        destroy(oldRx);                                  // scrub the previous s2c key now
        if (sessionId_.length == 0)
            sessionId_ = r.sessionId.dup; // fixed at the first KEX, preserved across rekeys
        state = TransportState(Established());
        bytesSinceKex = 0;
    }

    private void handleEstablished(SshMsg msg, const(ubyte)[] payload)
    {
        if (msg == SshMsg.kexInit)
        {
            startRekey(payload); // server-initiated rekey
            return;
        }
        events ~= payload.dup;
        accountAndMaybeRekey(payload.length);
    }

    // Send a fresh client KEXINIT and enter Kex (initiate a rekey, or respond to one).
    private void initiateRekey()
    {
        clientKexInit = makeClientKexInit();
        SshBuffer cb;
        clientKexInit.serialize(cb);
        clientKexInitBytes = cb.data;
        outbuf ~= tx.encryptPacket(clientKexInitBytes); // our KEXINIT
        state = TransportState(Kex());
    }

    // Server-initiated rekey: send our KEXINIT, then drive the server's (already received) one.
    private void startRekey(const(ubyte)[] serverKexInitPayload)
    {
        initiateRekey();
        handleKex(SshMsg.kexInit, serverKexInitPayload); // → KEX_ECDH_INIT
    }

    // Count app bytes through the connection; initiate a rekey once past the configured limit.
    private void accountAndMaybeRekey(size_t n)
    {
        bytesSinceKex += n;
        if (cfg.rekeyBytes != 0 && bytesSinceKex >= cfg.rekeyBytes
            && state.match!((Established _) => true, _ => false))
            initiateRekey();
    }

    private void flushAppOutQueue()
    {
        foreach (p; appOutQueue)
            outbuf ~= tx.encryptPacket(p);
        appOutQueue = null;
    }

    // Apply the user's trust policy to the (signature-verified) server host key.
    private void verifyHostKeyPolicy(const(ubyte)[] hostKeyBlob)
    {
        if (cfg.hostKeyVerifier is null)
            throw new SshConnectException("no host key verifier configured (fail-closed)");

        auto kb = SshBuffer(hostKeyBlob);
        HostKeyInfo info;
        info.host = host;
        info.port = port;
        info.keyType = kb.readStr();
        info.keyBlob = hostKeyBlob;
        info.fingerprintSha256 = "SHA256:" ~ fingerprintBase64(hostKeyBlob);
        info.known = KnownHostStatus.unknown; // known_hosts: v0.5

        if (cfg.hostKeyVerifier(info) == HostKeyDecision.reject)
            throw new SshHostKeyException("host key rejected by verifier");
    }

    private static string fingerprintBase64(const(ubyte)[] blob)
    {
        import std.base64 : Base64;

        auto s = Base64.encode(sha256(blob)[]);
        size_t end = s.length;
        while (end > 0 && s[end - 1] == '=')
            end--;
        return s[0 .. end].idup;
    }
}

unittest // full transport handshake against a simulated server, then an encrypted packet
{
    import dssh.crypto.openssl : ed25519Generate, ed25519Sign, x25519, x25519Generate;
    import dssh.transport : exchangeHash, deriveKey;

    SshConfig cfg;
    cfg.clientVersion = "SSH-2.0-dssh";
    cfg.hostKeyVerifier = (in HostKeyInfo) => HostKeyDecision.accept;
    auto core = ProtocolCore(cfg);
    core.start();

    auto srv = new PlaintextCipher; // server-side framing (PlaintextCipher is stateless)

    const(ubyte)[] takeLine(ref ubyte[] buf)
    {
        auto nl = buf.countUntil(cast(ubyte) '\n');
        assert(nl >= 0);
        size_t end = nl;
        if (end > 0 && buf[end - 1] == '\r')
            end--;
        auto line = buf[0 .. end];
        buf = buf[nl + 1 .. $];
        return line;
    }

    const(ubyte)[] takePacket(ref ubyte[] buf)
    {
        auto total = 4 + srv.trailingSize(buf[0 .. 4]);
        auto payload = srv.decryptPacket(buf[0 .. total]);
        buf = buf[total .. $];
        return payload;
    }

    // client banner + KEXINIT
    auto out1 = core.takeOutgoing();
    const(ubyte)[] vC = takeLine(out1);
    const(ubyte)[] iC = takePacket(out1);

    // server banner + KEXINIT
    const(ubyte)[] vS = cast(const(ubyte)[]) "SSH-2.0-srv";
    KexInit ski;
    ski.kex = ["curve25519-sha256"];
    ski.serverHostKey = ["ssh-ed25519"];
    ski.encryptionC2S = ["aes256-gcm@openssh.com"];
    ski.encryptionS2C = ["aes256-gcm@openssh.com"];
    ski.compressionC2S = ["none"];
    ski.compressionS2C = ["none"];
    SshBuffer skib;
    ski.serialize(skib);
    const(ubyte)[] iS = skib.data;

    core.feedIncoming(cast(const(ubyte)[]) "SSH-2.0-srv\r\n");
    core.feedIncoming(srv.encryptPacket(iS));

    // client KEX_ECDH_INIT
    auto out2 = core.takeOutgoing();
    auto ecdhInitPayload = takePacket(out2);
    auto eib = SshBuffer(ecdhInitPayload);
    const(ubyte)[] qc = KexEcdhInit.parse(eib).clientPublicKey;

    // server computes K, H and signs
    auto serverEph = x25519Generate();
    const(ubyte)[] qs = serverEph.publicKey[];
    auto K = x25519(serverEph.privateKey[], qc);
    auto hostKey = ed25519Generate();
    SshBuffer ksb;
    ksb.putStr("ssh-ed25519");
    ksb.putString(hostKey.publicKey[]);
    const(ubyte)[] ksBlob = ksb.data;
    auto H = exchangeHash(vC, vS, iC, iS, ksBlob, qc, qs, K[]);
    auto sigRaw = ed25519Sign(hostKey.privateKey[], H[]);
    SshBuffer sigb;
    sigb.putStr("ssh-ed25519");
    sigb.putString(sigRaw[]);

    // server KEX_ECDH_REPLY + NEW_KEYS
    SshBuffer rb;
    KexEcdhReply(ksBlob, qs, sigb.data).serialize(rb);
    core.feedIncoming(srv.encryptPacket(rb.data));
    SshBuffer nkb;
    NewKeys().serialize(nkb);
    core.feedIncoming(srv.encryptPacket(nkb.data));

    assert(core.transportEstablished());

    // client sent its NEW_KEYS (plaintext) before switching ciphers
    auto out3 = core.takeOutgoing();
    assert(takePacket(out3)[0] == cast(ubyte) SshMsg.newKeys);

    // a server-to-client encrypted packet is decrypted by the core
    auto serverCipher = new AesGcmCipher(deriveKey(K[], H[], H[], 'D', 32),
                                         deriveKey(K[], H[], H[], 'B', 12));
    ubyte[] secret = [0xde, 0xad, 0xbe, 0xef];
    core.feedIncoming(serverCipher.encryptPacket(secret));
    auto events = core.takeEvents();
    assert(events.length == 1);
    assert(events[0] == secret);
}

unittest // server-initiated rekey: new keys derived, session id preserved
{
    import dssh.crypto.openssl : ed25519Generate, ed25519Sign, x25519, x25519Generate;
    import dssh.transport : exchangeHash, deriveKey;

    SshConfig cfg;
    cfg.clientVersion = "SSH-2.0-dssh";
    cfg.hostKeyVerifier = (in HostKeyInfo) => HostKeyDecision.accept;
    auto core = ProtocolCore(cfg);
    core.start();

    auto hostKey = ed25519Generate();
    const(ubyte)[] vS = cast(const(ubyte)[]) "SSH-2.0-srv";
    SshBuffer ksb;
    ksb.putStr("ssh-ed25519");
    ksb.putString(hostKey.publicKey[]);
    const(ubyte)[] ksBlob = ksb.data;

    KexInit serverKexInit()
    {
        KexInit s;
        s.kex = ["curve25519-sha256"];
        s.serverHostKey = ["ssh-ed25519"];
        s.encryptionC2S = ["aes256-gcm@openssh.com"];
        s.encryptionS2C = ["aes256-gcm@openssh.com"];
        s.compressionC2S = ["none"];
        s.compressionS2C = ["none"];
        return s;
    }

    const(ubyte)[] takeLine(ref ubyte[] b)
    {
        auto nl = b.countUntil(cast(ubyte) '\n');
        assert(nl >= 0);
        size_t e = nl;
        if (e > 0 && b[e - 1] == '\r')
            e--;
        auto l = b[0 .. e];
        b = b[nl + 1 .. $];
        return l;
    }
    const(ubyte)[] take(PacketCipher c, ref ubyte[] b)
    {
        auto t = c.lengthFieldSize() + c.trailingSize(b[0 .. c.lengthFieldSize()]);
        auto p = c.decryptPacket(b[0 .. t]);
        b = b[t .. $];
        return p;
    }

    // ----- initial handshake (plaintext both ways) -----
    auto plain = new PlaintextCipher;
    auto out1 = core.takeOutgoing();
    const(ubyte)[] vC = takeLine(out1);
    const(ubyte)[] iC = take(plain, out1);

    SshBuffer sk1b;
    serverKexInit().serialize(sk1b);
    const(ubyte)[] iS = sk1b.data;
    core.feedIncoming(cast(const(ubyte)[]) "SSH-2.0-srv\r\n");
    core.feedIncoming(plain.encryptPacket(iS));

    auto out2 = core.takeOutgoing();
    auto eib1 = SshBuffer(take(plain, out2));
    const(ubyte)[] qc = KexEcdhInit.parse(eib1).clientPublicKey;
    auto eph1 = x25519Generate();
    const(ubyte)[] qs = eph1.publicKey[];
    auto K1 = x25519(eph1.privateKey[], qc);
    auto H1 = exchangeHash(vC, vS, iC, iS, ksBlob, qc, qs, K1[]);
    SshBuffer sig1;
    sig1.putStr("ssh-ed25519");
    sig1.putString(ed25519Sign(hostKey.privateKey[], H1[])[]);
    SshBuffer rb1;
    KexEcdhReply(ksBlob, qs, sig1.data).serialize(rb1);
    core.feedIncoming(plain.encryptPacket(rb1.data));
    SshBuffer nk1;
    NewKeys().serialize(nk1);
    core.feedIncoming(plain.encryptPacket(nk1.data));

    assert(core.transportEstablished());
    auto sid = core.sessionId().dup;
    assert(sid == H1[]);
    core.takeOutgoing(); // drain client NEWKEYS

    // established ciphers (server's view): read=client->server, write=server->client
    auto sRead = new AesGcmCipher(deriveKey(K1[], H1[], sid, 'C', 32), deriveKey(K1[], H1[], sid, 'A', 12));
    auto sWrite = new AesGcmCipher(deriveKey(K1[], H1[], sid, 'D', 32), deriveKey(K1[], H1[], sid, 'B', 12));

    // ----- server-initiated rekey (encrypted both ways) -----
    SshBuffer sk2b;
    serverKexInit().serialize(sk2b);
    const(ubyte)[] iS2 = sk2b.data;
    core.feedIncoming(sWrite.encryptPacket(iS2)); // server KEXINIT

    auto out4 = core.takeOutgoing();
    const(ubyte)[] iC2 = take(sRead, out4);             // client KEXINIT
    auto eib2 = SshBuffer(take(sRead, out4));
    const(ubyte)[] qc2 = KexEcdhInit.parse(eib2).clientPublicKey; // ECDH_INIT
    auto eph2 = x25519Generate();
    const(ubyte)[] qs2 = eph2.publicKey[];
    auto K2 = x25519(eph2.privateKey[], qc2);
    auto H2 = exchangeHash(vC, vS, iC2, iS2, ksBlob, qc2, qs2, K2[]);
    assert(H2[] != H1[]); // a fresh exchange hash
    SshBuffer sig2;
    sig2.putStr("ssh-ed25519");
    sig2.putString(ed25519Sign(hostKey.privateKey[], H2[])[]);
    SshBuffer rb2;
    KexEcdhReply(ksBlob, qs2, sig2.data).serialize(rb2);
    core.feedIncoming(sWrite.encryptPacket(rb2.data)); // ECDH_REPLY
    SshBuffer nk2;
    NewKeys().serialize(nk2);
    core.feedIncoming(sWrite.encryptPacket(nk2.data)); // server NEWKEYS

    auto out5 = core.takeOutgoing();
    assert(take(sRead, out5)[0] == cast(ubyte) SshMsg.newKeys); // client NEWKEYS (old c2s)

    // session id is unchanged across rekey
    assert(core.sessionId() == sid);

    // new keys derived with the PRESERVED session id; a packet under them decrypts
    auto sWrite2 = new AesGcmCipher(deriveKey(K2[], H2[], sid, 'D', 32), deriveKey(K2[], H2[], sid, 'B', 12));
    ubyte[] payload = [0x11, 0x22, 0x33];
    core.feedIncoming(sWrite2.encryptPacket(payload));
    auto evts = core.takeEvents();
    assert(evts.length == 1);
    assert(evts[0] == payload);
}

unittest // rekey deterministically scrubs the previous session keys (forward secrecy)
{
    import dssh.crypto.openssl : ed25519Generate, ed25519Sign, x25519, x25519Generate;
    import dssh.transport : exchangeHash, deriveKey;

    SshConfig cfg;
    cfg.clientVersion = "SSH-2.0-dssh";
    cfg.hostKeyVerifier = (in HostKeyInfo) => HostKeyDecision.accept;
    auto core = ProtocolCore(cfg);
    core.start();

    auto hostKey = ed25519Generate();
    const(ubyte)[] vS = cast(const(ubyte)[]) "SSH-2.0-srv";
    SshBuffer ksb;
    ksb.putStr("ssh-ed25519");
    ksb.putString(hostKey.publicKey[]);
    const(ubyte)[] ksBlob = ksb.data;

    KexInit sKex()
    {
        KexInit s;
        s.kex = ["curve25519-sha256"];
        s.serverHostKey = ["ssh-ed25519"];
        s.encryptionC2S = ["aes256-gcm@openssh.com"];
        s.encryptionS2C = ["aes256-gcm@openssh.com"];
        s.compressionC2S = ["none"];
        s.compressionS2C = ["none"];
        return s;
    }
    const(ubyte)[] takeLine(ref ubyte[] b)
    {
        auto nl = b.countUntil(cast(ubyte) '\n');
        size_t e = nl;
        if (e > 0 && b[e - 1] == '\r') e--;
        auto l = b[0 .. e];
        b = b[nl + 1 .. $];
        return l;
    }
    const(ubyte)[] take(PacketCipher c, ref ubyte[] b)
    {
        auto t = c.lengthFieldSize() + c.trailingSize(b[0 .. c.lengthFieldSize()]);
        auto p = c.decryptPacket(b[0 .. t]);
        b = b[t .. $];
        return p;
    }

    auto plain = new PlaintextCipher;
    auto out1 = core.takeOutgoing();
    const(ubyte)[] vC = takeLine(out1);
    const(ubyte)[] iC = take(plain, out1);

    SshBuffer sk1b;
    sKex().serialize(sk1b);
    const(ubyte)[] iS = sk1b.data;
    core.feedIncoming(cast(const(ubyte)[]) "SSH-2.0-srv\r\n");
    core.feedIncoming(plain.encryptPacket(iS));

    auto out2 = core.takeOutgoing();
    auto eib = SshBuffer(take(plain, out2));
    const(ubyte)[] qc = KexEcdhInit.parse(eib).clientPublicKey;
    auto eph = x25519Generate();
    auto K = x25519(eph.privateKey[], qc);
    auto H = exchangeHash(vC, vS, iC, iS, ksBlob, qc, eph.publicKey[], K[]);
    SshBuffer sig;
    sig.putStr("ssh-ed25519");
    sig.putString(ed25519Sign(hostKey.privateKey[], H[])[]);
    SshBuffer rb;
    KexEcdhReply(ksBlob, eph.publicKey[], sig.data).serialize(rb);
    core.feedIncoming(plain.encryptPacket(rb.data));
    SshBuffer nk;
    NewKeys().serialize(nk);
    core.feedIncoming(plain.encryptPacket(nk.data));
    core.takeOutgoing(); // drain client NEWKEYS

    auto sid = core.sessionId().dup;
    auto sRead = new AesGcmCipher(deriveKey(K[], H[], sid, 'C', 32), deriveKey(K[], H[], sid, 'A', 12));
    auto sWrite = new AesGcmCipher(deriveKey(K[], H[], sid, 'D', 32), deriveKey(K[], H[], sid, 'B', 12));

    // Capture the live ciphers before rekey; both must be scrubbed by the rekey path.
    auto oldTx = cast(AesGcmCipher) core.tx;
    auto oldRx = cast(AesGcmCipher) core.rx;
    assert(oldTx !is null && oldRx !is null);
    ubyte[32] zero;
    assert(oldTx.sessionKeyForVerify() != zero); // sanity: not already zero

    // ----- server-initiated rekey -----
    SshBuffer sk2b;
    sKex().serialize(sk2b);
    const(ubyte)[] iS2 = sk2b.data;
    core.feedIncoming(sWrite.encryptPacket(iS2));
    auto out4 = core.takeOutgoing();
    const(ubyte)[] iC2 = take(sRead, out4);
    auto eib2 = SshBuffer(take(sRead, out4));
    const(ubyte)[] qc2 = KexEcdhInit.parse(eib2).clientPublicKey;
    auto eph2 = x25519Generate();
    auto K2 = x25519(eph2.privateKey[], qc2);
    auto H2 = exchangeHash(vC, vS, iC2, iS2, ksBlob, qc2, eph2.publicKey[], K2[]);
    SshBuffer sig2;
    sig2.putStr("ssh-ed25519");
    sig2.putString(ed25519Sign(hostKey.privateKey[], H2[])[]);
    SshBuffer rb2;
    KexEcdhReply(ksBlob, eph2.publicKey[], sig2.data).serialize(rb2);
    core.feedIncoming(sWrite.encryptPacket(rb2.data));
    SshBuffer nk2;
    NewKeys().serialize(nk2);
    core.feedIncoming(sWrite.encryptPacket(nk2.data));

    // After rekey both old session keys must be zeroized; otherwise the previous
    // key sits in the GC heap until a future collection (forward-secrecy gap).
    assert(oldTx.sessionKeyForVerify() == zero);
    assert(oldRx.sessionKeyForVerify() == zero);
}

unittest // a byte-volume threshold triggers a client-initiated rekey
{
    import dssh.crypto.openssl : ed25519Generate, ed25519Sign, x25519, x25519Generate;
    import dssh.transport : exchangeHash, deriveKey;

    SshConfig cfg;
    cfg.clientVersion = "SSH-2.0-dssh";
    cfg.hostKeyVerifier = (in HostKeyInfo) => HostKeyDecision.accept;
    cfg.rekeyBytes = 64; // tiny, so a single app packet crosses it
    auto core = ProtocolCore(cfg);
    core.start();

    auto hostKey = ed25519Generate();
    const(ubyte)[] vS = cast(const(ubyte)[]) "SSH-2.0-srv";
    SshBuffer ksb;
    ksb.putStr("ssh-ed25519");
    ksb.putString(hostKey.publicKey[]);
    const(ubyte)[] ksBlob = ksb.data;

    const(ubyte)[] takeLine(ref ubyte[] b)
    {
        auto nl = b.countUntil(cast(ubyte) '\n');
        assert(nl >= 0);
        size_t e = nl;
        if (e > 0 && b[e - 1] == '\r')
            e--;
        auto l = b[0 .. e];
        b = b[nl + 1 .. $];
        return l;
    }
    const(ubyte)[] take(PacketCipher c, ref ubyte[] b)
    {
        auto t = c.lengthFieldSize() + c.trailingSize(b[0 .. c.lengthFieldSize()]);
        auto p = c.decryptPacket(b[0 .. t]);
        b = b[t .. $];
        return p;
    }

    // establish
    auto plain = new PlaintextCipher;
    auto out1 = core.takeOutgoing();
    const(ubyte)[] vC = takeLine(out1);
    const(ubyte)[] iC = take(plain, out1);
    KexInit ski;
    ski.kex = ["curve25519-sha256"];
    ski.serverHostKey = ["ssh-ed25519"];
    ski.encryptionC2S = ["aes256-gcm@openssh.com"];
    ski.encryptionS2C = ["aes256-gcm@openssh.com"];
    ski.compressionC2S = ["none"];
    ski.compressionS2C = ["none"];
    SshBuffer skib;
    ski.serialize(skib);
    const(ubyte)[] iS = skib.data;
    core.feedIncoming(cast(const(ubyte)[]) "SSH-2.0-srv\r\n");
    core.feedIncoming(plain.encryptPacket(iS));
    auto out2 = core.takeOutgoing();
    auto eib = SshBuffer(take(plain, out2));
    const(ubyte)[] qc = KexEcdhInit.parse(eib).clientPublicKey;
    auto eph = x25519Generate();
    auto K = x25519(eph.privateKey[], qc);
    auto H = exchangeHash(vC, vS, iC, iS, ksBlob, qc, eph.publicKey[], K[]);
    SshBuffer sig;
    sig.putStr("ssh-ed25519");
    sig.putString(ed25519Sign(hostKey.privateKey[], H[])[]);
    SshBuffer rb;
    KexEcdhReply(ksBlob, eph.publicKey[], sig.data).serialize(rb);
    core.feedIncoming(plain.encryptPacket(rb.data));
    SshBuffer nk;
    NewKeys().serialize(nk);
    core.feedIncoming(plain.encryptPacket(nk.data));
    assert(core.transportEstablished());
    core.takeOutgoing(); // drain client NEWKEYS

    auto sRead = new AesGcmCipher(deriveKey(K[], H[], H[], 'C', 32), deriveKey(K[], H[], H[], 'A', 12));

    // an app packet bigger than rekeyBytes must be followed by a client-initiated KEXINIT
    ubyte[] big = new ubyte[100];
    core.sendPacket(big);
    auto outb = core.takeOutgoing();
    take(sRead, outb);           // the app packet itself
    auto kx = take(sRead, outb); // the KEXINIT the core appended
    assert(kx[0] == cast(ubyte) SshMsg.kexInit);
}

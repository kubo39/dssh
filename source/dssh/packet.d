/// SSH binary packet cipher.
module dssh.packet;

import std.bitmanip : nativeToBigEndian, bigEndianToNative;
import dssh.exception : SshProtocolException;
import dssh.crypto.openssl : OpenSslAesGcm, randomBytes;
import dssh.secret : secureZero;

/// Upper bound on a complete wire packet (length field + ciphertext + tag). The length
/// field is attacker-influenced before authentication, so the framing layer must reject
/// oversized claims instead of buffering toward them. Matches OpenSSH's 256 KiB limit.
enum size_t maxWirePacket = 256 * 1024;

interface PacketCipher
{
    /// Frame and encrypt a payload into a complete wire packet.
    ubyte[] encryptPacket(const(ubyte)[] payload);
    /// Cleartext bytes the framing layer reads before it knows the packet size.
    size_t lengthFieldSize() const;
    /// Trailing bytes (ciphertext + tag) after the length field, given that field.
    size_t trailingSize(const(ubyte)[] lengthField) const;
    /// Verify + decrypt a complete wire packet, returning the payload. Throws on failure.
    const(ubyte)[] decryptPacket(const(ubyte)[] packet);
}

// RFC 5647: the 8-byte invocation counter (iv[4..12]) is a big-endian integer incremented
// after each packet; the 4-byte fixed field iv[0..4] is left unchanged.
private void incrementGcmIv(ref ubyte[12] iv)
{
    foreach_reverse (i; 4 .. 12)
        if (++iv[i] != 0)
            break;
}

/// aes256-gcm@openssh.com: packet_length is cleartext AAD, the rest is AES-256-GCM.
final class AesGcmCipher : PacketCipher
{
    private enum tagLength = 16;
    private enum blockSize = 16;

    private OpenSslAesGcm gcm;
    private ubyte[32] key;
    private ubyte[12] iv;

    this(const(ubyte)[] key, const(ubyte)[] iv)
    {
        if (key.length != 32)
            throw new SshProtocolException("AES-256-GCM key must be 32 bytes");
        if (iv.length != 12)
            throw new SshProtocolException("AES-GCM IV must be 12 bytes");
        this.key[] = key[];
        this.iv[] = iv[];
        gcm = new OpenSslAesGcm;
    }

    // Scrub the session key on destruction (deterministic via ProtocolCore.~this on close()).
    ~this() @nogc nothrow { secureZero(key[]); }

    // Direct (non-vtable) call so unittests can read the key after destroy() to verify scrub.
    package ubyte[32] sessionKeyForVerify() const @safe @nogc nothrow { return key; }

    size_t lengthFieldSize() const { return 4; }

    size_t trailingSize(const(ubyte)[] lengthField) const
    {
        ubyte[4] lf = lengthField[0 .. 4];
        return bigEndianToNative!uint(lf) + tagLength;
    }

    ubyte[] encryptPacket(const(ubyte)[] payload)
    {
        // (padding_length || payload || padding) must be a multiple of blockSize, padding >= 4.
        const unpadded = 1 + payload.length;
        size_t pad = blockSize - (unpadded % blockSize);
        if (pad < 4)
            pad += blockSize;
        const encLen = cast(uint)(unpadded + pad);

        auto plaintext = new ubyte[encLen];
        plaintext[0] = cast(ubyte) pad;
        plaintext[1 .. 1 + payload.length] = payload[];
        randomBytes(plaintext[1 + payload.length .. $]);

        ubyte[4] lengthField = nativeToBigEndian(encLen);
        ubyte[] ciphertext;
        ubyte[16] tag;
        gcm.seal(key[], iv[], lengthField[], plaintext, ciphertext, tag);
        incrementGcmIv(iv);

        return lengthField[] ~ ciphertext ~ tag[];
    }

    const(ubyte)[] decryptPacket(const(ubyte)[] packet)
    {
        if (packet.length < 4 + tagLength)
            throw new SshProtocolException("short SSH packet");
        ubyte[4] lengthField = packet[0 .. 4];
        const encLen = bigEndianToNative!uint(lengthField);
        if (packet.length != 4 + encLen + tagLength)
            throw new SshProtocolException("SSH packet length mismatch");
        // (padding_length || payload || padding) is at least one block and block-aligned
        // (RFC 5647 framing); checked before decryption so plaintext[0] below is in bounds.
        if (encLen < blockSize || encLen % blockSize != 0)
            throw new SshProtocolException("bad SSH packet length");

        auto ciphertext = packet[4 .. 4 + encLen];
        ubyte[16] tag = packet[4 + encLen .. 4 + encLen + tagLength];
        ubyte[] plaintext;
        if (!gcm.open(key[], iv[], lengthField[], ciphertext, tag, plaintext))
            throw new SshProtocolException("packet authentication failed");
        incrementGcmIv(iv);

        const pad = plaintext[0];
        if (pad < 4 || pad > encLen - 1)
            throw new SshProtocolException("bad SSH padding length");
        return plaintext[1 .. encLen - pad];
    }
}

unittest // GCM IV is a big-endian counter over the last 8 bytes; fixed field untouched
{
    ubyte[12] iv = 0;
    incrementGcmIv(iv);
    ubyte[12] one = 0;
    one[11] = 1;
    assert(iv == one);

    ubyte[12] carry = 0;
    carry[11] = 0xff;
    incrementGcmIv(carry);
    ubyte[12] expected = 0;
    expected[10] = 1;
    assert(carry == expected);

    ubyte[12] wrap = 0;
    wrap[0] = 0xaa;
    foreach (i; 4 .. 12) wrap[i] = 0xff;
    incrementGcmIv(wrap);
    assert(wrap[0] == 0xaa);
    foreach (i; 4 .. 12) assert(wrap[i] == 0);
}

version (unittest) private AesGcmCipher testCipher()
{
    ubyte[32] key;
    foreach (i; 0 .. 32) key[i] = cast(ubyte) i;
    ubyte[12] iv;
    foreach (i; 0 .. 12) iv[i] = cast(ubyte)(0x10 + i);
    return new AesGcmCipher(key[], iv[]);
}

unittest // packet round-trip recovers the payload
{
    auto enc = testCipher();
    auto dec = testCipher();
    ubyte[] payload = [1, 2, 3, 4, 5, 6, 7];
    assert(dec.decryptPacket(enc.encryptPacket(payload)) == payload);
}

unittest // wire structure: cleartext length, encrypted portion multiple of 16, 16-byte tag
{
    auto c = testCipher();
    ubyte[] payload = [0xAB];
    auto packet = c.encryptPacket(payload);
    ubyte[4] lf = packet[0 .. 4];
    uint encLen = bigEndianToNative!uint(lf);
    assert(encLen % 16 == 0);
    assert(packet.length == 4 + encLen + 16);
}

unittest // consecutive packets stay in sync as the IV advances
{
    auto enc = testCipher();
    auto dec = testCipher();
    ubyte[] p1 = [0xaa];
    ubyte[] p2 = [0xbb, 0xcc];
    auto w1 = enc.encryptPacket(p1);
    auto w2 = enc.encryptPacket(p2);
    assert(dec.decryptPacket(w1) == p1);
    assert(dec.decryptPacket(w2) == p2);
    // the same payload yields different ciphertext once the IV has advanced
    assert(enc.encryptPacket(p1) != enc.encryptPacket(p1));
}

unittest // encLen == 0 with a VALID tag is a protocol error, not a range crash
{
    import std.exception : assertThrown;

    // An authenticated peer can frame a packet whose encrypted portion is empty; the
    // padding byte then does not exist and naive plaintext[0] would be out of bounds.
    ubyte[32] key;
    foreach (i; 0 .. 32) key[i] = cast(ubyte) i;
    ubyte[12] iv;
    foreach (i; 0 .. 12) iv[i] = cast(ubyte)(0x10 + i);

    auto gcm = new OpenSslAesGcm;
    ubyte[4] lengthField = 0; // encLen == 0
    ubyte[] ciphertext;
    ubyte[16] tag;
    gcm.seal(key[], iv[], lengthField[], null, ciphertext, tag);

    auto dec = testCipher(); // same key/IV as the forged seal above
    assertThrown!SshProtocolException(dec.decryptPacket(lengthField[] ~ tag[]));
}

unittest // a tampered tag fails authentication
{
    import std.exception : assertThrown;
    auto enc = testCipher();
    auto dec = testCipher();
    ubyte[] payload = [1, 2, 3];
    auto packet = enc.encryptPacket(payload);
    packet[$ - 1] ^= 0xff;
    assertThrown!SshProtocolException(dec.decryptPacket(packet));
}

/// "none" cipher: unencrypted binary packet framing, used before NEW_KEYS (RFC 4253 §6).
final class PlaintextCipher : PacketCipher
{
    private enum blockSize = 8;

    ubyte[] encryptPacket(const(ubyte)[] payload)
    {
        // (length_field(4) + padding_length(1) + payload + padding) % 8 == 0, padding >= 4.
        const unpadded = 4 + 1 + payload.length;
        size_t pad = blockSize - (unpadded % blockSize);
        if (pad < 4)
            pad += blockSize;
        const packetLength = cast(uint)(1 + payload.length + pad);

        auto wire = new ubyte[4 + packetLength];
        wire[0 .. 4] = nativeToBigEndian(packetLength);
        wire[4] = cast(ubyte) pad;
        wire[5 .. 5 + payload.length] = payload[];
        randomBytes(wire[5 + payload.length .. $]);
        return wire;
    }

    size_t lengthFieldSize() const { return 4; }

    size_t trailingSize(const(ubyte)[] lengthField) const
    {
        ubyte[4] lf = lengthField[0 .. 4];
        return bigEndianToNative!uint(lf); // no tag for "none"
    }

    const(ubyte)[] decryptPacket(const(ubyte)[] packet)
    {
        if (packet.length < 5)
            throw new SshProtocolException("short SSH packet");
        ubyte[4] lf = packet[0 .. 4];
        const packetLength = bigEndianToNative!uint(lf);
        if (packet.length != 4 + packetLength)
            throw new SshProtocolException("SSH packet length mismatch");

        const pad = packet[4];
        if (pad < 4 || pad > packetLength - 1)
            throw new SshProtocolException("bad SSH padding length");
        return packet[5 .. 4 + packetLength - pad];
    }
}

unittest // plaintext packet round-trip recovers the payload
{
    auto c = new PlaintextCipher;
    ubyte[] payload = [1, 2, 3, 4, 5];
    assert(c.decryptPacket(c.encryptPacket(payload)) == payload);
}

unittest // plaintext wire is a multiple of 8 with no trailing tag
{
    auto c = new PlaintextCipher;
    ubyte[] payload = [0xAB];
    auto packet = c.encryptPacket(payload);
    assert(packet.length % 8 == 0);
    ubyte[4] lf = packet[0 .. 4];
    assert(c.trailingSize(lf) + 4 == packet.length); // no tag
}

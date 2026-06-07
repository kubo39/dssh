/// Key formats and loading.
module dssh.keys;

import std.base64 : Base64;
import dssh.exception : SshProtocolException;
import dssh.wire : SshBuffer;
import dssh.secret : SecretBuf, secureZero;

/// Holds the ed25519 private seed in a non-copyable, zeroized SecretBuf; move-only.
struct SshKey
{
    string keyType;         // "ssh-ed25519"
    ubyte[] publicKey;      // raw 32-byte ed25519 public key
    SecretBuf privateSeed;  // raw ed25519 seed (malloc-backed, zeroized on destruction)

    this(string keyType, ubyte[] publicKey, scope const(ubyte)[] seed)
    {
        this.keyType = keyType;
        this.publicKey = publicKey;
        privateSeed = SecretBuf(seed.length);
        auto dst = privateSeed[];
        dst[] = seed[];
    }

    /// SSH public key blob: string(keyType) || string(publicKey).
    const(ubyte)[] publicKeyBlob() const
    {
        SshBuffer b;
        b.putStr(keyType);
        b.putString(publicKey);
        return b.data;
    }
}

// bcrypt-pbkdf rounds are attacker-controllable via the key file; cap them so a hostile
// file cannot force unbounded work. Far above OpenSSH's default (16) or any sane choice.
private enum maxBcryptRounds = 1000;

// Strip PEM armor and base64-decode the "openssh-key-v1" blob.
private ubyte[] pemToBlob(const(char)[] pem)
{
    import std.string : lineSplitter, strip;
    import std.array : appender;

    auto b64 = appender!string;
    bool inside;
    foreach (line; pem.lineSplitter)
    {
        auto t = line.strip;
        if (t == "-----BEGIN OPENSSH PRIVATE KEY-----") { inside = true; continue; }
        if (t == "-----END OPENSSH PRIVATE KEY-----") break;
        if (inside && t.length)
            b64 ~= t;
    }
    if (b64.data.length == 0)
        throw new SshProtocolException("not an OpenSSH private key");
    return Base64.decode(b64.data);
}

private void requireMagic(ref SshBuffer b)
{
    if (b.readRaw(15) != cast(const(ubyte)[]) "openssh-key-v1\0")
        throw new SshProtocolException("bad OpenSSH key magic");
}

// Parse the (decrypted) private section: checkint, key type, public + private blobs.
// `section` is scrubbed before returning; the ed25519 seed survives inside the SecretBuf.
private SshKey parseInnerKey(ubyte[] section)
{
    scope (exit) secureZero(section);
    auto sb = SshBuffer(section);
    const check1 = sb.readUint32();
    const check2 = sb.readUint32();
    if (check1 != check2)
        throw new SshProtocolException("OpenSSH key checkint mismatch (wrong passphrase?)");
    const keyType = sb.readStr();
    if (keyType != "ssh-ed25519")
        throw new SshProtocolException("unsupported key type: " ~ keyType);

    auto pub = sb.readString().dup;        // 32 bytes
    auto seed = sb.readString()[0 .. 32];  // 64 bytes = seed || public; keep the seed
    return SshKey(keyType, pub, seed);
}

/// Parse an unencrypted OpenSSH ed25519 private key from its PEM text. For dev/test use;
/// production code should keep keys encrypted and use the passphrase overload.
SshKey parseOpenSshPrivateKey(const(char)[] pem)
{
    auto decoded = pemToBlob(pem);
    scope (exit) secureZero(decoded); // wipe the plaintext key material left by parsing
    auto b = SshBuffer(decoded);
    requireMagic(b);
    if (b.readStr() != "none")
        throw new SshProtocolException("encrypted OpenSSH private keys require a passphrase");
    b.readStr();    // kdfname ("none")
    b.readString(); // kdfoptions (empty)
    if (b.readUint32() != 1)
        throw new SshProtocolException("multi-key OpenSSH files are not supported");
    b.readString(); // public key blob (re-derived from the private section)
    return parseInnerKey(b.readString().dup);
}

/// Parse an encrypted OpenSSH ed25519 private key (cipher aes256-ctr, kdf bcrypt) using
/// `passphrase` (interpreted as UTF-8 bytes). The passphrase must be non-empty.
SshKey parseOpenSshPrivateKey(const(char)[] pem, string passphrase)
{
    import std.string : representation;
    import dssh.crypto.bcrypt : bcryptPbkdf;
    import dssh.crypto.openssl : aes256CtrDecrypt;

    if (passphrase.length == 0)
        throw new SshProtocolException("passphrase must not be empty");

    auto decoded = pemToBlob(pem);
    scope (exit) secureZero(decoded);
    auto b = SshBuffer(decoded);
    requireMagic(b);
    const cipher = b.readStr();
    const kdf = b.readStr();
    if (cipher == "none")
        throw new SshProtocolException("key is not encrypted; load it without a passphrase");
    if (cipher != "aes256-ctr")
        throw new SshProtocolException("unsupported cipher: " ~ cipher);
    if (kdf != "bcrypt")
        throw new SshProtocolException("unsupported kdf: " ~ kdf);

    auto opts = SshBuffer(b.readString());
    auto salt = opts.readString().dup;
    const rounds = opts.readUint32();
    if (rounds < 1 || rounds > maxBcryptRounds)
        throw new SshProtocolException("bcrypt rounds out of range");

    if (b.readUint32() != 1)
        throw new SshProtocolException("multi-key OpenSSH files are not supported");
    b.readString(); // public key blob
    auto ct = b.readString();
    if (ct.length == 0 || ct.length % 16 != 0)
        throw new SshProtocolException("bad encrypted private section length");

    // Derive 32-byte AES key || 16-byte IV from the passphrase, then unwrap the section.
    auto keyiv = bcryptPbkdf(passphrase.representation, salt, 48, rounds);
    scope (exit) secureZero(keyiv);
    return parseInnerKey(aes256CtrDecrypt(keyiv[0 .. 32], keyiv[32 .. 48], ct));
}

/// Load an unencrypted OpenSSH private key from a file. For encrypted
/// (passphrase-protected) keys use the passphrase overload below.
SshKey loadPrivateKey(string path)
{
    import std.file : readText;

    return parseOpenSshPrivateKey(readText(path));
}

/// Load an encrypted OpenSSH private key (cipher aes256-ctr, kdf bcrypt) from a file.
SshKey loadPrivateKey(string path, string passphrase)
{
    import std.file : readText;

    return parseOpenSshPrivateKey(readText(path), passphrase);
}

unittest // parse a real unencrypted OpenSSH ed25519 private key
{
    import dssh.crypto.openssl : ed25519Sign, ed25519Verify;

    // Throwaway key generated only for this parser test; never used as a real credential.
    enum pem = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAPhptWVnT6fjxLBZghpCKwNyMFFVJUQWXDbgstng3cEwAAAJD9rDtd/aw7
XQAAAAtzc2gtZWQyNTUxOQAAACAPhptWVnT6fjxLBZghpCKwNyMFFVJUQWXDbgstng3cEw
AAAECDz5cMJgusfbArCj79TL+eWY8gTE8EO/2CHuSRrcdx3w+Gm1ZWdPp+PEsFmCGkIrA3
IwUVUlRBZcNuCy2eDdwTAAAADXB1cmVkc3NoLXRlc3Q=
-----END OPENSSH PRIVATE KEY-----`;

    auto key = parseOpenSshPrivateKey(pem);
    assert(key.keyType == "ssh-ed25519");
    assert(key.publicKey.length == 32);
    assert(key.privateSeed.length == 32);

    // the extracted keypair is internally consistent
    ubyte[] msg = [1, 2, 3, 4];
    assert(ed25519Verify(key.publicKey, msg, ed25519Sign(key.privateSeed[], msg)));

    // public key blob is well-formed
    auto bb = SshBuffer(key.publicKeyBlob());
    assert(bb.readStr() == "ssh-ed25519");
    assert(bb.readString() == key.publicKey);
}

unittest // parse an ENCRYPTED OpenSSH ed25519 private key (bcrypt + aes256-ctr)
{
    import dssh.crypto.openssl : ed25519Sign, ed25519Verify;
    import std.conv : to;

    // Throwaway key generated only for this test; the passphrase is public on purpose.
    enum pem = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBipHzvtZ
d1yl3FdicGbybpAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIFhGIR6ElR9Hel7t
3PhUKXQFWdhyRcnEQckWWFabuBrLAAAAoJPtHVaxFlJklNCUQqRF0Evma8iteWEJ9ZX1hF
ZM6YboMpfFaXbrQNDTqgosnNpCD+EoYng9X2ECrFHRBr8JCTa8L+fGRtE/xt11cd/I/EV5
tQ82w6eUfsx2BjqgMZM3BbfBrw+HPf+b5Kr9wGbnH5FCYja6u1eALqpFO3RzUjy7VXj71h
ITRjIDyFTQFDrD0R1aoFzRWzpEko/NRI7MUKA=
-----END OPENSSH PRIVATE KEY-----`;

    ubyte[] hex(string h)
    {
        ubyte[] r;
        foreach (i; 0 .. h.length / 2)
            r ~= h[2 * i .. 2 * i + 2].to!ubyte(16);
        return r;
    }

    auto key = parseOpenSshPrivateKey(pem, "correct horse");
    assert(key.keyType == "ssh-ed25519");
    assert(key.publicKey ==
        hex("5846211e84951f477a5eeddcf85429740559d87245c9c441c91658569bb81acb"));
    assert(key.privateSeed.length == 32);

    ubyte[] msg = [1, 2, 3, 4];
    assert(ed25519Verify(key.publicKey, msg, ed25519Sign(key.privateSeed[], msg)));

    // Wrong passphrase derives a different AES key; decryption yields garbage whose
    // checkint fails -- we must reject it, never return a bogus key.
    import std.exception : assertThrown;
    assertThrown!SshProtocolException(parseOpenSshPrivateKey(pem, "wrong passphrase"));
    // An empty passphrase is rejected outright.
    assertThrown!SshProtocolException(parseOpenSshPrivateKey(pem, ""));
}

unittest // loadPrivateKey reads an encrypted key file when given the passphrase
{
    import std.file : write, remove, tempDir;
    import std.path : buildPath;

    // Same throwaway key as the parse test above; the passphrase is public on purpose.
    enum pem = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBipHzvtZ
d1yl3FdicGbybpAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIFhGIR6ElR9Hel7t
3PhUKXQFWdhyRcnEQckWWFabuBrLAAAAoJPtHVaxFlJklNCUQqRF0Evma8iteWEJ9ZX1hF
ZM6YboMpfFaXbrQNDTqgosnNpCD+EoYng9X2ECrFHRBr8JCTa8L+fGRtE/xt11cd/I/EV5
tQ82w6eUfsx2BjqgMZM3BbfBrw+HPf+b5Kr9wGbnH5FCYja6u1eALqpFO3RzUjy7VXj71h
ITRjIDyFTQFDrD0R1aoFzRWzpEko/NRI7MUKA=
-----END OPENSSH PRIVATE KEY-----`;

    const path = buildPath(tempDir, "dssh_enc_key_test");
    write(path, pem);
    scope (exit)
        remove(path);

    auto key = loadPrivateKey(path, "correct horse");
    assert(key.keyType == "ssh-ed25519");
    assert(key.privateSeed.length == 32);
}

unittest // SshKey is non-copyable: the private seed lives in a move-only SecretBuf
{
    static assert(!__traits(compiles, (SshKey a) { SshKey b = a; }));
}

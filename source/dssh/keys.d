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

/// Parse an unencrypted OpenSSH ed25519 private key from its PEM text.
SshKey parseOpenSshPrivateKey(const(char)[] pem)
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

    auto decoded = Base64.decode(b64.data);
    scope (exit) secureZero(decoded); // wipe the plaintext key material left by parsing
    auto b = SshBuffer(decoded);
    if (b.readRaw(15) != cast(const(ubyte)[]) "openssh-key-v1\0")
        throw new SshProtocolException("bad OpenSSH key magic");
    if (b.readStr() != "none")
        throw new SshProtocolException("encrypted OpenSSH private keys are not supported");
    b.readStr();    // kdfname ("none")
    b.readString(); // kdfoptions (empty)
    if (b.readUint32() != 1)
        throw new SshProtocolException("multi-key OpenSSH files are not supported");
    b.readString(); // public key blob (re-derived from the private section)

    auto sb = SshBuffer(b.readString());
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

/// Load an unencrypted OpenSSH private key from a file. Encrypted (passphrase-protected)
/// keys are not supported; decrypting them needs bcrypt-pbkdf, which we deliberately do
/// not implement.
SshKey loadPrivateKey(string path)
{
    import std.file : readText;

    return parseOpenSshPrivateKey(readText(path));
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

unittest // SshKey is non-copyable: the private seed lives in a move-only SecretBuf
{
    static assert(!__traits(compiles, (SshKey a) { SshKey b = a; }));
}

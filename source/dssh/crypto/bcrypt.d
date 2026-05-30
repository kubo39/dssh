/// OpenSSH bcrypt_pbkdf key-derivation (used by encrypted OpenSSH private keys).
///
/// The 16-round Blowfish block is OpenSSL's `BF_encrypt`; only the EksBlowfish schedule
/// + PBKDF striding are assembled here. SHA-512 is OpenSSL's. We never hand-roll a
/// cryptographic primitive. The pi-init constants live in dssh.crypto.bcrypt_tables
/// (public standard data).
module dssh.crypto.bcrypt;

import deimos.openssl.blowfish : BF_KEY, BF_encrypt;
import deimos.openssl.evp : EVP_Digest, EVP_sha512;
import dssh.crypto.bcrypt_tables : sBoxInit, pArrayInit;
import dssh.exception : SshProtocolException;
import dssh.secret : secureZero;

private enum hashSize = 32; // BCRYPT_HASHSIZE
private enum words = 8;     // BCRYPT_BLOCKS

private ubyte[64] sha512(scope const(ubyte)[] data) @trusted
{
    ubyte[64] digest;
    uint len;
    if (EVP_Digest(data.ptr, data.length, digest.ptr, &len, EVP_sha512(), null) != 1)
        throw new SshProtocolException("SHA-512 failed");
    return digest;
}

// One Blowfish block via OpenSSL (matches OpenBSD Blowfish_encipher for identical P/S).
private void encipher(ref BF_KEY c, ref uint xl, ref uint xr) @trusted
{
    uint[2] d = [xl, xr];
    BF_encrypt(d.ptr, &c);
    xl = d[0];
    xr = d[1];
}

// Read 4 bytes big-endian from `data`, cycling, advancing cursor `j`.
private uint stream2word(scope const(ubyte)[] data, ref size_t j) @safe @nogc nothrow
{
    uint temp = 0;
    foreach (_; 0 .. 4)
    {
        if (j >= data.length)
            j = 0;
        temp = (temp << 8) | data[j];
        j++;
    }
    return temp;
}

private void initstate(ref BF_KEY c) @trusted @nogc nothrow
{
    c.P[] = pArrayInit[];
    c.S[] = sBoxInit[];
}

private void expandstate(ref BF_KEY c, scope const(ubyte)[] data,
                         scope const(ubyte)[] key) @trusted
{
    size_t j = 0;
    foreach (i; 0 .. 18)
        c.P[i] ^= stream2word(key, j);

    j = 0;
    uint datal = 0, datar = 0;
    for (size_t i = 0; i < 18; i += 2)
    {
        datal ^= stream2word(data, j);
        datar ^= stream2word(data, j);
        encipher(c, datal, datar);
        c.P[i] = datal;
        c.P[i + 1] = datar;
    }
    foreach (sb; 0 .. 4)
        for (size_t k = 0; k < 256; k += 2)
        {
            datal ^= stream2word(data, j);
            datar ^= stream2word(data, j);
            encipher(c, datal, datar);
            c.S[sb * 256 + k] = datal;
            c.S[sb * 256 + k + 1] = datar;
        }
}

private void expand0state(ref BF_KEY c, scope const(ubyte)[] key) @trusted
{
    size_t j = 0;
    foreach (i; 0 .. 18)
        c.P[i] ^= stream2word(key, j);

    uint datal = 0, datar = 0;
    for (size_t i = 0; i < 18; i += 2)
    {
        encipher(c, datal, datar);
        c.P[i] = datal;
        c.P[i + 1] = datar;
    }
    foreach (sb; 0 .. 4)
        for (size_t k = 0; k < 256; k += 2)
        {
            encipher(c, datal, datar);
            c.S[sb * 256 + k] = datal;
            c.S[sb * 256 + k + 1] = datar;
        }
}

private void bcryptHash(scope const(ubyte)[] sha2pass, scope const(ubyte)[] sha2salt,
                        ref ubyte[hashSize] outp) @trusted
{
    enum magic = "OxychromaticBlowfishSwatDynamite"; // 32 bytes
    BF_KEY state;
    uint[words] cdata;

    initstate(state);
    expandstate(state, sha2salt, sha2pass);
    foreach (_; 0 .. 64)
    {
        expand0state(state, sha2salt);
        expand0state(state, sha2pass);
    }

    size_t j = 0;
    foreach (i; 0 .. words)
        cdata[i] = stream2word(cast(const(ubyte)[]) magic, j);
    foreach (_; 0 .. 64)
        for (size_t b = 0; b < words; b += 2)
            encipher(state, cdata[b], cdata[b + 1]);

    foreach (i; 0 .. words)
    {
        outp[4 * i + 3] = cast(ubyte)(cdata[i] >> 24);
        outp[4 * i + 2] = cast(ubyte)(cdata[i] >> 16);
        outp[4 * i + 1] = cast(ubyte)(cdata[i] >> 8);
        outp[4 * i + 0] = cast(ubyte) cdata[i];
    }
    secureZero((cast(ubyte*) cdata.ptr)[0 .. cdata.sizeof]);
    secureZero((cast(ubyte*)&state)[0 .. state.sizeof]);
}

/// Derive `keylen` bytes from `pass` / `salt` over `rounds` iterations
/// (Provos & Mazieres bcrypt hash + PBKDF2-style block striding).
ubyte[] bcryptPbkdf(scope const(ubyte)[] pass, scope const(ubyte)[] salt,
                    size_t keylen, uint rounds) @trusted
{
    if (rounds < 1 || pass.length == 0 || salt.length == 0 || keylen == 0)
        throw new SshProtocolException("bcrypt_pbkdf: invalid parameters");

    auto key = new ubyte[keylen];
    const origkeylen = keylen;
    const stride = (keylen + hashSize - 1) / hashSize;
    auto amt = (keylen + stride - 1) / stride;

    auto countsalt = new ubyte[salt.length + 4];
    countsalt[0 .. salt.length] = salt[];

    ubyte[64] sha2pass = sha512(pass);
    ubyte[64] sha2salt;
    ubyte[hashSize] outb, tmpout;

    for (uint count = 1; keylen > 0; count++)
    {
        countsalt[salt.length + 0] = cast(ubyte)(count >> 24);
        countsalt[salt.length + 1] = cast(ubyte)(count >> 16);
        countsalt[salt.length + 2] = cast(ubyte)(count >> 8);
        countsalt[salt.length + 3] = cast(ubyte) count;

        sha2salt = sha512(countsalt);
        bcryptHash(sha2pass[], sha2salt[], tmpout);
        outb = tmpout;

        foreach (_; 1 .. rounds)
        {
            sha2salt = sha512(tmpout[]);
            bcryptHash(sha2pass[], sha2salt[], tmpout);
            foreach (k; 0 .. hashSize)
                outb[k] ^= tmpout[k];
        }

        if (amt > keylen)
            amt = keylen;
        size_t i;
        for (i = 0; i < amt; i++)
        {
            const dest = i * stride + (count - 1);
            if (dest >= origkeylen)
                break;
            key[dest] = outb[i];
        }
        keylen -= i;
    }

    secureZero(sha2pass[]);
    secureZero(sha2salt[]);
    secureZero(outb[]);
    secureZero(tmpout[]);
    return key;
}

unittest // KATs from pyca bcrypt.kdf (== OpenSSH bcrypt_pbkdf)
{
    import std.conv : to;

    ubyte[] hex(string h)
    {
        ubyte[] r;
        foreach (i; 0 .. h.length / 2)
            r ~= h[2 * i .. 2 * i + 2].to!ubyte(16);
        return r;
    }

    const pw = cast(const(ubyte)[]) "password";
    const salt = cast(const(ubyte)[]) "salt";

    assert(bcryptPbkdf(pw, salt, 32, 16) ==
        hex("c3d7ec5f693f16055b6d2f0af904795f79a924bbeb6fbdb805e82409d56d1e63"));
    assert(bcryptPbkdf(pw, salt, 48, 16) ==
        hex("c339d704ec235f27690d3f12167c05a55bf86d572f270adbf9fe04c379da5f8c"
          ~ "7942a939245dbb39ebe26fc2bd19b88b"));
    assert(bcryptPbkdf(pw, salt, 64, 16) ==
        hex("c339d704ec235f27690d3f12167c05a55bf86d572f270adbf9fe04c379da5f8c"
          ~ "7942a939245dbb39ebe26fc2bd19b88b05f3e85024c509d5d5db6d821e7663e2"));

    ubyte[16] bsalt;
    foreach (i, ref b; bsalt)
        b = cast(ubyte) i;
    assert(bcryptPbkdf(cast(const(ubyte)[]) "topsecret", bsalt[], 48, 32) ==
        hex("9e9681ffe9182203e6fa4c3722e24186e22a93935195e971de02f839c6696e1c"
          ~ "7be36abc047b25ac02e97f3d80cc3d70"));
}

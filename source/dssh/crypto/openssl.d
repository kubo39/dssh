/// OpenSSL backend: AES-256-GCM. dub: openssl (deimos bindings).
module dssh.crypto.openssl;

import deimos.openssl.evp;
import deimos.openssl.rand : RAND_bytes;
import deimos.openssl.hmac : HMAC;
import dssh.crypto.api : AeadCipher;
import dssh.exception : SshException;

private void check(int rc, string what)
{
    if (rc != 1)
        throw new SshException("OpenSSL " ~ what ~ " failed");
}

/// aes256-gcm@openssh.com.
final class OpenSslAesGcm : AeadCipher
{
    void seal(const(ubyte)[] key, const(ubyte)[] nonce,
              const(ubyte)[] aad, const(ubyte)[] plaintext,
              ref ubyte[] ciphertext, ref ubyte[16] tag)
    {
        auto ctx = EVP_CIPHER_CTX_new();
        if (ctx is null)
            throw new SshException("EVP_CIPHER_CTX_new failed");
        scope (exit)
            EVP_CIPHER_CTX_free(ctx);

        check(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), null, null, null), "EncryptInit cipher");
        check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, cast(int) nonce.length, null), "set IV length");
        check(EVP_EncryptInit_ex(ctx, null, null, key.ptr, nonce.ptr), "EncryptInit key/IV");

        int outl;
        if (aad.length)
            check(EVP_EncryptUpdate(ctx, null, &outl, aad.ptr, cast(int) aad.length), "AAD");

        ciphertext = new ubyte[plaintext.length];
        if (plaintext.length)
            check(EVP_EncryptUpdate(ctx, ciphertext.ptr, &outl, plaintext.ptr, cast(int) plaintext.length), "encrypt");

        ubyte scratch;
        int finalLen;
        check(EVP_EncryptFinal_ex(ctx, &scratch, &finalLen), "EncryptFinal");
        check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.ptr), "get tag");
    }

    bool open(const(ubyte)[] key, const(ubyte)[] nonce,
              const(ubyte)[] aad, const(ubyte)[] ciphertext,
              const(ubyte)[16] tag, ref ubyte[] plaintext)
    {
        auto ctx = EVP_CIPHER_CTX_new();
        if (ctx is null)
            throw new SshException("EVP_CIPHER_CTX_new failed");
        scope (exit)
            EVP_CIPHER_CTX_free(ctx);

        check(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), null, null, null), "DecryptInit cipher");
        check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, cast(int) nonce.length, null), "set IV length");
        check(EVP_DecryptInit_ex(ctx, null, null, key.ptr, nonce.ptr), "DecryptInit key/IV");

        int outl;
        if (aad.length)
            check(EVP_DecryptUpdate(ctx, null, &outl, aad.ptr, cast(int) aad.length), "AAD");

        plaintext = new ubyte[ciphertext.length];
        if (ciphertext.length)
            check(EVP_DecryptUpdate(ctx, plaintext.ptr, &outl, ciphertext.ptr, cast(int) ciphertext.length), "decrypt");

        check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, cast(void*) tag.ptr), "set tag");

        ubyte scratch;
        int finalLen;
        return EVP_DecryptFinal_ex(ctx, &scratch, &finalLen) > 0; // tag verification
    }
}

unittest // McGrew/NIST AES-256-GCM test case 14
{
    auto c = new OpenSslAesGcm;
    ubyte[32] key = 0;
    ubyte[12] iv = 0;
    ubyte[16] pt = 0;
    ubyte[] ct;
    ubyte[16] tag;
    c.seal(key[], iv[], null, pt[], ct, tag);

    ubyte[] expectedCt = [
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
        0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18];
    ubyte[16] expectedTag = [
        0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
        0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19];
    assert(ct == expectedCt);
    assert(tag == expectedTag);
}

unittest // round-trip with AAD
{
    auto c = new OpenSslAesGcm;
    ubyte[32] key;
    foreach (i; 0 .. 32) key[i] = cast(ubyte) i;
    ubyte[12] iv;
    foreach (i; 0 .. 12) iv[i] = cast(ubyte)(i + 1);
    ubyte[] aad = [0xaa, 0xbb];
    ubyte[] pt = [1, 2, 3, 4, 5];

    ubyte[] ct;
    ubyte[16] tag;
    c.seal(key[], iv[], aad, pt, ct, tag);

    ubyte[] recovered;
    assert(c.open(key[], iv[], aad, ct, tag, recovered));
    assert(recovered == pt);
}

unittest // corrupted tag fails authentication
{
    auto c = new OpenSslAesGcm;
    ubyte[32] key = 0;
    ubyte[12] iv = 0;
    ubyte[] pt = [1, 2, 3];

    ubyte[] ct;
    ubyte[16] tag;
    c.seal(key[], iv[], null, pt, ct, tag);
    tag[0] ^= 0xff;

    ubyte[] recovered;
    assert(!c.open(key[], iv[], null, ct, tag, recovered));
}

unittest // AAD mismatch fails authentication
{
    auto c = new OpenSslAesGcm;
    ubyte[32] key = 0;
    ubyte[12] iv = 0;
    ubyte[] pt = [9, 9, 9];

    ubyte[] ct;
    ubyte[16] tag;
    c.seal(key[], iv[], [ubyte(1)], pt, ct, tag);

    ubyte[] recovered;
    assert(!c.open(key[], iv[], [ubyte(2)], ct, tag, recovered));
}

private void need32(const(ubyte)[] x, string what)
{
    if (x.length != 32)
        throw new SshException(what ~ " must be 32 bytes");
}

/// SHA-256 digest (used for the KEX exchange hash and key derivation).
ubyte[32] sha256(const(ubyte)[] data)
{
    ubyte[32] digest;
    uint len;
    if (EVP_Digest(data.ptr, data.length, digest.ptr, &len, EVP_sha256(), null) != 1)
        throw new SshException("SHA-256 failed");
    return digest;
}

unittest // FIPS 180 SHA-256("abc")
{
    ubyte[] msg = [0x61, 0x62, 0x63];
    ubyte[32] expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad];
    assert(sha256(msg) == expected);
}

struct X25519KeyPair
{
    ubyte[32] privateKey; // ephemeral KEX secret; scrubbed after use (see ClientKex)
    ubyte[32] publicKey;
}

/// X25519 scalar multiplication: shared secret from our private and the peer's public.
ubyte[32] x25519(const(ubyte)[] privateKey, const(ubyte)[] peerPublic)
{
    need32(privateKey, "X25519 private key");
    need32(peerPublic, "X25519 peer public key");

    auto priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, null, privateKey.ptr, 32);
    if (priv is null)
        throw new SshException("X25519 import private key failed");
    scope (exit)
        EVP_PKEY_free(priv);

    auto peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, null, peerPublic.ptr, 32);
    if (peer is null)
        throw new SshException("X25519 import peer public key failed");
    scope (exit)
        EVP_PKEY_free(peer);

    auto ctx = EVP_PKEY_CTX_new(priv, null);
    if (ctx is null)
        throw new SshException("X25519 derive context failed");
    scope (exit)
        EVP_PKEY_CTX_free(ctx);

    check(EVP_PKEY_derive_init(ctx), "derive init");
    check(EVP_PKEY_derive_set_peer(ctx, peer), "derive set peer");

    ubyte[32] secret;
    size_t len = secret.length;
    check(EVP_PKEY_derive(ctx, secret.ptr, &len), "derive");
    return secret;
}

/// Generate an ephemeral X25519 keypair.
X25519KeyPair x25519Generate()
{
    X25519KeyPair kp;
    if (RAND_bytes(kp.privateKey.ptr, 32) != 1)
        throw new SshException("RAND_bytes failed");
    ubyte[32] basepoint = 0;
    basepoint[0] = 9; // X25519 base point u=9
    kp.publicKey = x25519(kp.privateKey, basepoint);
    return kp;
}

unittest // RFC 7748 X25519 test vector
{
    ubyte[32] alicePriv = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a];
    ubyte[32] bobPub = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f];
    ubyte[32] expectedShared = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
        0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42];
    assert(x25519(alicePriv, bobPub) == expectedShared);
}

unittest // generated keypairs agree on a shared secret
{
    auto a = x25519Generate();
    auto b = x25519Generate();
    assert(x25519(a.privateKey, b.publicKey) == x25519(b.privateKey, a.publicKey));
}

/// Verify an Ed25519 signature over message with the 32-byte public key.
bool ed25519Verify(const(ubyte)[] publicKey, const(ubyte)[] message, const(ubyte)[] signature)
{
    need32(publicKey, "Ed25519 public key");

    auto pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, null, publicKey.ptr, 32);
    if (pub is null)
        throw new SshException("Ed25519 import public key failed");
    scope (exit)
        EVP_PKEY_free(pub);

    auto mdctx = EVP_MD_CTX_new();
    if (mdctx is null)
        throw new SshException("EVP_MD_CTX_new failed");
    scope (exit)
        EVP_MD_CTX_free(mdctx);

    check(EVP_DigestVerifyInit(mdctx, null, null, null, pub), "DigestVerifyInit");
    return EVP_DigestVerify(mdctx, signature.ptr, signature.length, message.ptr, message.length) == 1;
}

unittest // RFC 8032 Ed25519 test 1 (empty message)
{
    ubyte[32] pub = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a];
    ubyte[64] sig = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
        0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
        0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
        0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b];
    ubyte[] msg = [];
    assert(ed25519Verify(pub, msg, sig[]));
}

unittest // tampered Ed25519 signature is rejected
{
    ubyte[32] pub = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a];
    ubyte[64] sig = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
        0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
        0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
        0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b];
    sig[0] ^= 0xff;
    ubyte[] msg = [];
    assert(!ed25519Verify(pub, msg, sig[]));
}

struct Ed25519KeyPair
{
    ubyte[32] privateKey; // server host key (test/server-sim use; client auth key is SshKey)
    ubyte[32] publicKey;
}

/// Generate an Ed25519 keypair (server host key; also used to simulate a server in tests).
Ed25519KeyPair ed25519Generate()
{
    auto pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, null);
    if (pctx is null)
        throw new SshException("Ed25519 keygen context failed");
    scope (exit)
        EVP_PKEY_CTX_free(pctx);

    check(EVP_PKEY_keygen_init(pctx), "keygen init");
    EVP_PKEY* pkey;
    check(EVP_PKEY_keygen(pctx, &pkey), "keygen");
    scope (exit)
        EVP_PKEY_free(pkey);

    Ed25519KeyPair kp;
    size_t len = kp.publicKey.length;
    check(EVP_PKEY_get_raw_public_key(pkey, kp.publicKey.ptr, &len), "get raw public");
    len = kp.privateKey.length;
    check(EVP_PKEY_get_raw_private_key(pkey, kp.privateKey.ptr, &len), "get raw private");
    return kp;
}

/// Sign message with an Ed25519 private key (server side).
ubyte[64] ed25519Sign(const(ubyte)[] privateKey, const(ubyte)[] message)
{
    need32(privateKey, "Ed25519 private key");

    auto priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, null, privateKey.ptr, 32);
    if (priv is null)
        throw new SshException("Ed25519 import private key failed");
    scope (exit)
        EVP_PKEY_free(priv);

    auto mdctx = EVP_MD_CTX_new();
    if (mdctx is null)
        throw new SshException("EVP_MD_CTX_new failed");
    scope (exit)
        EVP_MD_CTX_free(mdctx);

    check(EVP_DigestSignInit(mdctx, null, null, null, priv), "DigestSignInit");
    ubyte[64] sig;
    size_t siglen = sig.length;
    check(EVP_DigestSign(mdctx, sig.ptr, &siglen, message.ptr, message.length), "DigestSign");
    return sig;
}

unittest // Ed25519 generate + sign + verify round-trip
{
    auto kp = ed25519Generate();
    ubyte[] msg = [0x01, 0x02, 0x03];
    auto sig = ed25519Sign(kp.privateKey[], msg);
    assert(ed25519Verify(kp.publicKey[], msg, sig[]));

    auto bad = sig;
    bad[0] ^= 0xff;
    assert(!ed25519Verify(kp.publicKey[], msg, bad[]));
}

/// HMAC-SHA1. Used only to match hashed known_hosts host names (not for SSH transport crypto).
ubyte[20] hmacSha1(const(ubyte)[] key, const(ubyte)[] data) @trusted
{
    ubyte[20] mac;
    uint len;
    if (HMAC(EVP_sha1(), key.ptr, cast(int) key.length, data.ptr, data.length, mac.ptr, &len) is null)
        throw new SshException("HMAC-SHA1 failed");
    return mac;
}

unittest // RFC 2202 HMAC-SHA1 test case 1
{
    ubyte[20] key = 0x0b;
    ubyte[] data = cast(ubyte[]) "Hi There".dup;
    ubyte[20] expected = [
        0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b,
        0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00];
    assert(hmacSha1(key[], data) == expected);
}

/// Fill buf with cryptographically secure random bytes.
void randomBytes(ubyte[] buf)
{
    if (buf.length && RAND_bytes(buf.ptr, cast(int) buf.length) != 1)
        throw new SshException("RAND_bytes failed");
}

unittest // randomBytes fills the buffer with varying data
{
    ubyte[] a = new ubyte[32];
    ubyte[] b = new ubyte[32];
    randomBytes(a);
    randomBytes(b);
    assert(a != b);
}

/// AES-256-CTR decrypt. Used to unwrap the private section of an encrypted OpenSSH key
/// (a stream cipher, so output length equals input length).
ubyte[] aes256CtrDecrypt(scope const(ubyte)[] key, scope const(ubyte)[] iv,
                         scope const(ubyte)[] ciphertext) @trusted
{
    assert(key.length == 32 && iv.length == 16);
    auto ctx = EVP_CIPHER_CTX_new();
    if (ctx is null)
        throw new SshException("EVP_CIPHER_CTX_new failed");
    scope (exit)
        EVP_CIPHER_CTX_free(ctx);

    check(EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), null, key.ptr, iv.ptr), "DecryptInit");
    auto outp = new ubyte[ciphertext.length];
    int outl;
    check(EVP_DecryptUpdate(ctx, outp.ptr, &outl, ciphertext.ptr,
            cast(int) ciphertext.length), "DecryptUpdate");
    int finalLen;
    check(EVP_DecryptFinal_ex(ctx, outp.ptr + outl, &finalLen), "DecryptFinal");
    return outp;
}

unittest // AES-256-CTR decrypt(encrypt(x)) == x (CTR is symmetric)
{
    ubyte[32] key = 0x11;
    ubyte[16] iv = 0x22;
    auto pt = cast(const(ubyte)[]) "the private section of an openssh key";
    // Encrypt by running CTR over the plaintext, then decrypt the result.
    auto ct = aes256CtrDecrypt(key[], iv[], pt);
    assert(ct != pt);
    assert(aes256CtrDecrypt(key[], iv[], ct) == pt);
}

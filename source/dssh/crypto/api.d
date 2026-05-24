/// Crypto backend abstraction; OpenSSL-only behind this interface.
module dssh.crypto.api;

interface AeadCipher
{
    void seal(const(ubyte)[] key, const(ubyte)[] nonce,
              const(ubyte)[] aad, const(ubyte)[] plaintext,
              ref ubyte[] ciphertext, ref ubyte[16] tag);
    bool open(const(ubyte)[] key, const(ubyte)[] nonce,
              const(ubyte)[] aad, const(ubyte)[] ciphertext,
              const(ubyte)[16] tag, ref ubyte[] plaintext);
}

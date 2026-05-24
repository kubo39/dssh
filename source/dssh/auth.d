/// Authentication methods and request building.
module dssh.auth;

import std.algorithm.mutation : move;
import dssh.keys : SshKey;
import dssh.messages : SshMsg, UserauthPublicKeyRequest;
import dssh.wire : SshBuffer;
import dssh.exception : SshProtocolException;
import dssh.crypto.openssl : ed25519Sign;

/// Tagged auth method value built by the factories below.
struct AuthMethod
{
    private enum Kind { none, publicKey, password }
    private Kind kind;
    private SshKey key;
    private string password;
}

AuthMethod publicKey(SshKey key) { AuthMethod m; m.kind = AuthMethod.Kind.publicKey; m.key = move(key); return m; }
AuthMethod password(string pw)   { AuthMethod m; m.kind = AuthMethod.Kind.password; m.password = pw; return m; }
AuthMethod none()                { AuthMethod m; m.kind = AuthMethod.Kind.none; return m; }

struct AuthResult
{
    bool success;
    bool partialSuccess;
    string[] remaining; // methods that can continue (USERAUTH_FAILURE name-list)
}

/// Serialize a USERAUTH_REQUEST for the given method. publickey requests are signed.
const(ubyte)[] buildAuthRequest(const ref AuthMethod m, const(ubyte)[] sessionId, string user, string service)
{
    final switch (m.kind)
    {
    case AuthMethod.Kind.publicKey:
        return buildPublicKeyRequest(sessionId, user, service, m.key);
    case AuthMethod.Kind.password:
        throw new SshProtocolException("password auth not implemented yet");
    case AuthMethod.Kind.none:
        throw new SshProtocolException("none method has no request");
    }
}

private const(ubyte)[] buildPublicKeyRequest(const(ubyte)[] sessionId, string user, string service,
                                             const ref SshKey key)
{
    // Signed data (RFC 4252 §7): session id, then the request fields up to the public key blob.
    SshBuffer signed;
    signed.putString(sessionId);
    signed.putByte(SshMsg.userauthRequest);
    signed.putStr(user);
    signed.putStr(service);
    signed.putStr("publickey");
    signed.putBool(true);
    signed.putStr(key.keyType);
    signed.putString(key.publicKeyBlob());
    auto sig = ed25519Sign(key.privateSeed[], signed.data);

    // Signature blob: string(algorithm) || string(signature).
    SshBuffer sigBlob;
    sigBlob.putStr(key.keyType);
    sigBlob.putString(sig[]);

    SshBuffer b;
    UserauthPublicKeyRequest(user, service, key.keyType, key.publicKeyBlob(), sigBlob.data).serialize(b);
    return b.data;
}

unittest // publickey USERAUTH_REQUEST carries a valid ed25519 signature
{
    import dssh.crypto.openssl : ed25519Generate, ed25519Verify;

    auto kp = ed25519Generate();
    auto pub = kp.publicKey.dup;
    auto pubBlob = SshKey("ssh-ed25519", pub, kp.privateKey[]).publicKeyBlob();
    auto m = publicKey(SshKey("ssh-ed25519", pub, kp.privateKey[]));
    ubyte[] sessionId = [0xaa, 0xbb, 0xcc];

    auto reqBytes = buildAuthRequest(m, sessionId, "alice", "ssh-connection");
    auto pb = SshBuffer(reqBytes);
    auto req = UserauthPublicKeyRequest.parse(pb);
    assert(req.user == "alice");

    // reconstruct the signed data and verify the embedded signature
    SshBuffer signed;
    signed.putString(sessionId);
    signed.putByte(SshMsg.userauthRequest);
    signed.putStr("alice");
    signed.putStr("ssh-connection");
    signed.putStr("publickey");
    signed.putBool(true);
    signed.putStr("ssh-ed25519");
    signed.putString(pubBlob);

    auto sb = SshBuffer(req.signature);
    assert(sb.readStr() == "ssh-ed25519");
    assert(ed25519Verify(pub, signed.data, sb.readString()));
}

/// Host key verification: verifier delegate + built-in helpers.
module dssh.hostkey;

enum HostKeyDecision { accept, reject }

enum KnownHostStatus { unknown, matched, changed }

struct HostKeyInfo
{
    string host;
    ushort port;
    string keyType;
    const(ubyte)[] keyBlob;
    string fingerprintSha256;
    KnownHostStatus known;
}

alias HostKeyVerifier = HostKeyDecision delegate(in HostKeyInfo) @safe;

/// Accept iff the server key's SHA-256 fingerprint matches. Accepts the OpenSSH
/// "SHA256:<base64>" form or the bare base64 (the public key is not secret, so a plain
/// comparison is fine).
HostKeyVerifier acceptFingerprint(string sha256) @safe
{
    import std.algorithm.searching : skipOver;

    string expected = sha256;
    expected.skipOver("SHA256:");
    return (in HostKeyInfo info) {
        string actual = info.fingerprintSha256;
        actual.skipOver("SHA256:");
        return actual == expected ? HostKeyDecision.accept : HostKeyDecision.reject;
    };
}

/// Verify against an OpenSSH known_hosts file. Supports plain host names, `[host]:port`,
/// and hashed (`|1|salt|hash`) entries, and `@revoked` markers. Unknown hosts and changed
/// keys are rejected (fail-closed; no interactive trust-on-first-use). `@cert-authority`
/// and wildcard patterns are not yet supported.
HostKeyVerifier knownHosts(string path = "~/.ssh/known_hosts") @safe
{
    return (in HostKeyInfo info) {
        import std.path : expandTilde;
        import std.string : lineSplitter, strip;
        import std.array : split;
        import std.algorithm.searching : startsWith;
        import std.base64 : Base64;
        import std.conv : to;

        // @trusted: a plain file read, no unsafe aliasing escapes the block.
        string content;
        const present = () @trusted {
            import std.file : exists, readText;
            auto p = expandTilde(path);
            if (!p.exists)
                return false;
            content = readText(p);
            return true;
        }();
        if (!present)
            return HostKeyDecision.reject; // fail-closed: no known_hosts

        const lookup = (info.port == 0 || info.port == 22)
            ? info.host : "[" ~ info.host ~ "]:" ~ info.port.to!string;

        bool accept;
        foreach (line; content.lineSplitter)
        {
            auto t = line.strip;
            if (t.length == 0 || t[0] == '#')
                continue;
            auto f = t.split;
            size_t i;
            bool revoked;
            if (f.length && f[i].startsWith("@"))
            {
                if (f[i] == "@revoked")
                    revoked = true;
                else
                    continue; // @cert-authority etc: unsupported
                i++;
            }
            if (f.length < i + 3)
                continue;
            if (f[i + 1] != info.keyType)
                continue;
            if (!hostFieldMatches(f[i], lookup))
                continue;
            const(ubyte)[] blob;
            try
                blob = Base64.decode(f[i + 2]);
            catch (Exception)
                continue;
            if (blob != info.keyBlob)
                continue; // host+type match but different key → changed; keep scanning
            if (revoked)
                return HostKeyDecision.reject; // explicit revocation wins
            accept = true;
        }
        return accept ? HostKeyDecision.accept : HostKeyDecision.reject;
    };
}

// Match one known_hosts host field against the canonical lookup name (host or [host]:port).
private bool hostFieldMatches(string hostField, string lookup) @safe
{
    import std.array : split;
    import std.algorithm.searching : startsWith;
    import std.base64 : Base64;
    import dssh.crypto.openssl : hmacSha1;

    if (hostField.startsWith("|1|"))
    {
        auto parts = hostField.split("|"); // ["", "1", salt, hash]
        if (parts.length != 4)
            return false;
        ubyte[] salt, hash;
        try
        {
            salt = Base64.decode(parts[2]);
            hash = Base64.decode(parts[3]);
        }
        catch (Exception)
            return false;
        return hmacSha1(salt, cast(const(ubyte)[]) lookup)[] == hash;
    }
    foreach (h; hostField.split(","))
        if (h == lookup)
            return true;
    return false;
}

/// Accept any host key. Insecure; for tests only.
HostKeyVerifier insecureAcceptAll() @safe
{
    return (in HostKeyInfo) => HostKeyDecision.accept;
}

@safe unittest // acceptFingerprint matches with or without the SHA256: prefix
{
    HostKeyInfo info;
    info.fingerprintSha256 = "SHA256:Zm9vYmFy";
    assert(acceptFingerprint("SHA256:Zm9vYmFy")(info) == HostKeyDecision.accept);
    assert(acceptFingerprint("Zm9vYmFy")(info) == HostKeyDecision.accept);
    assert(acceptFingerprint("SHA256:other")(info) == HostKeyDecision.reject);
}

unittest // knownHosts: plain + hashed match, changed key + unknown host rejected
{
    import dssh.crypto.openssl : ed25519Generate, hmacSha1;
    import dssh.wire : SshBuffer;
    import std.base64 : Base64;
    import std.file : write, remove, tempDir;
    import std.path : buildPath;

    string blobBase64(ubyte[] pub)
    {
        SshBuffer b;
        b.putStr("ssh-ed25519");
        b.putString(pub);
        return Base64.encode(b.data).idup;
    }

    auto kp = ed25519Generate();
    SshBuffer kb;
    kb.putStr("ssh-ed25519");
    kb.putString(kp.publicKey[]);
    const(ubyte)[] blob = kb.data;
    const b64 = Base64.encode(blob).idup;
    const otherB64 = blobBase64(ed25519Generate().publicKey[]);

    // hashed entry for "hashed.example": |1|b64(salt)|b64(HMAC-SHA1(salt, name))
    ubyte[20] salt;
    foreach (i; 0 .. 20)
        salt[i] = cast(ubyte) i;
    auto mac = hmacSha1(salt[], cast(const(ubyte)[]) "hashed.example");
    const hashedField = "|1|" ~ Base64.encode(salt[]).idup ~ "|" ~ Base64.encode(mac[]).idup;

    const path = buildPath(tempDir, "dssh_known_hosts_test");
    write(path,
        "plain.example ssh-ed25519 " ~ b64 ~ "\n" ~
        hashedField ~ " ssh-ed25519 " ~ b64 ~ "\n" ~
        "changed.example ssh-ed25519 " ~ otherB64 ~ "\n");
    scope (exit)
        remove(path);

    auto verify = knownHosts(path);
    HostKeyInfo info;
    info.keyType = "ssh-ed25519";
    info.keyBlob = blob;
    info.port = 22;

    info.host = "plain.example";
    assert(verify(info) == HostKeyDecision.accept);
    info.host = "hashed.example";
    assert(verify(info) == HostKeyDecision.accept);
    info.host = "changed.example";
    assert(verify(info) == HostKeyDecision.reject); // key differs
    info.host = "unknown.example";
    assert(verify(info) == HostKeyDecision.reject); // not present
}

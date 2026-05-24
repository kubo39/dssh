/// SSH message numbers (RFC 4250/4253/4254).
module dssh.messages;

import dssh.wire : SshBuffer;
import dssh.exception : SshProtocolException;

enum SshMsg : ubyte
{
    // transport (RFC 4253)
    disconnect = 1,
    ignore = 2,
    unimplemented = 3,
    debug_ = 4,
    serviceRequest = 5,
    serviceAccept = 6,
    extInfo = 7,
    kexInit = 20,
    newKeys = 21,
    kexEcdhInit = 30,
    kexEcdhReply = 31,

    // authentication (RFC 4252)
    userauthRequest = 50,
    userauthFailure = 51,
    userauthSuccess = 52,
    userauthBanner = 53,

    // connection (RFC 4254)
    globalRequest = 80,
    requestSuccess = 81,
    requestFailure = 82,
    channelOpen = 90,
    channelOpenConfirmation = 91,
    channelOpenFailure = 92,
    channelWindowAdjust = 93,
    channelData = 94,
    channelExtendedData = 95,
    channelEof = 96,
    channelClose = 97,
    channelRequest = 98,
    channelSuccess = 99,
    channelFailure = 100,
}

enum SshExtendedDataType : uint
{
    stderr = 1,
}

/// Read and validate the leading message-number byte.
private void expectMsg(ref SshBuffer b, SshMsg expected) @safe
{
    if (b.readByte() != expected)
        throw new SshProtocolException("unexpected message type");
}

/// SSH_MSG_KEXINIT (RFC 4253 §7.1).
struct KexInit
{
    ubyte[16] cookie;
    string[] kex;
    string[] serverHostKey;
    string[] encryptionC2S;
    string[] encryptionS2C;
    string[] macC2S;
    string[] macS2C;
    string[] compressionC2S;
    string[] compressionS2C;
    string[] languagesC2S;
    string[] languagesS2C;
    bool firstKexPacketFollows;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.kexInit);
        b.putRaw(cookie[]);
        b.putNameList(kex);
        b.putNameList(serverHostKey);
        b.putNameList(encryptionC2S);
        b.putNameList(encryptionS2C);
        b.putNameList(macC2S);
        b.putNameList(macS2C);
        b.putNameList(compressionC2S);
        b.putNameList(compressionS2C);
        b.putNameList(languagesC2S);
        b.putNameList(languagesS2C);
        b.putBool(firstKexPacketFollows);
        b.putUint32(0); // reserved
    }

    static KexInit parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.kexInit);
        KexInit m;
        m.cookie = b.readRaw(16);
        m.kex = b.readNameList();
        m.serverHostKey = b.readNameList();
        m.encryptionC2S = b.readNameList();
        m.encryptionS2C = b.readNameList();
        m.macC2S = b.readNameList();
        m.macS2C = b.readNameList();
        m.compressionC2S = b.readNameList();
        m.compressionS2C = b.readNameList();
        m.languagesC2S = b.readNameList();
        m.languagesS2C = b.readNameList();
        m.firstKexPacketFollows = b.readBool();
        b.readUint32(); // reserved
        return m;
    }
}

/// SSH_MSG_SERVICE_REQUEST (RFC 4253 §10).
struct ServiceRequest
{
    string serviceName;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.serviceRequest);
        b.putString(cast(const(ubyte)[]) serviceName);
    }

    static ServiceRequest parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.serviceRequest);
        return ServiceRequest(cast(string) b.readString().idup);
    }
}

@safe unittest
{
    auto m = ServiceRequest("ssh-userauth");
    SshBuffer b;
    m.serialize(b);
    assert(ServiceRequest.parse(b) == m);
}

@safe unittest
{
    KexInit m;
    m.cookie = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    m.kex = ["curve25519-sha256"];
    m.serverHostKey = ["ssh-ed25519"];
    m.encryptionC2S = ["aes256-gcm@openssh.com"];
    m.encryptionS2C = ["aes256-gcm@openssh.com"];
    m.compressionC2S = ["none"];
    m.compressionS2C = ["none"];

    SshBuffer b;
    m.serialize(b);
    auto parsed = KexInit.parse(b);
    assert(parsed == m);
}

/// SSH_MSG_CHANNEL_DATA (RFC 4254 §5.2).
struct ChannelData
{
    uint recipientChannel;
    const(ubyte)[] data;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.channelData);
        b.putUint32(recipientChannel);
        b.putString(data);
    }

    static ChannelData parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.channelData);
        ChannelData m;
        m.recipientChannel = b.readUint32();
        m.data = b.readString();
        return m;
    }
}

@safe unittest
{
    ubyte[] payload = [0x68, 0x69];
    auto m = ChannelData(7, payload);
    SshBuffer b;
    m.serialize(b);
    assert(ChannelData.parse(b) == m);
}

/// SSH_MSG_NEWKEYS (RFC 4253 §7.3).
struct NewKeys
{
    void serialize(ref SshBuffer b) const @safe { b.putByte(SshMsg.newKeys); }
    static NewKeys parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.newKeys);
        return NewKeys();
    }
}

/// SSH_MSG_DISCONNECT (RFC 4253 §11.1).
struct Disconnect
{
    uint reasonCode;
    string description;
    string languageTag;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.disconnect);
        b.putUint32(reasonCode);
        b.putStr(description);
        b.putStr(languageTag);
    }

    static Disconnect parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.disconnect);
        Disconnect m;
        m.reasonCode = b.readUint32();
        m.description = b.readStr();
        m.languageTag = b.readStr();
        return m;
    }
}

/// SSH_MSG_SERVICE_ACCEPT (RFC 4253 §10).
struct ServiceAccept
{
    string serviceName;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.serviceAccept);
        b.putStr(serviceName);
    }

    static ServiceAccept parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.serviceAccept);
        return ServiceAccept(b.readStr());
    }
}

/// SSH_MSG_KEX_ECDH_INIT (curve25519-sha256, msg 30): client ephemeral public key.
struct KexEcdhInit
{
    const(ubyte)[] clientPublicKey;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.kexEcdhInit);
        b.putString(clientPublicKey);
    }

    static KexEcdhInit parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.kexEcdhInit);
        KexEcdhInit m;
        m.clientPublicKey = b.readString();
        return m;
    }
}

/// SSH_MSG_KEX_ECDH_REPLY (msg 31): host key, server ephemeral public key, signature.
struct KexEcdhReply
{
    const(ubyte)[] hostKey;
    const(ubyte)[] serverPublicKey;
    const(ubyte)[] signature;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.kexEcdhReply);
        b.putString(hostKey);
        b.putString(serverPublicKey);
        b.putString(signature);
    }

    static KexEcdhReply parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.kexEcdhReply);
        KexEcdhReply m;
        m.hostKey = b.readString();
        m.serverPublicKey = b.readString();
        m.signature = b.readString();
        return m;
    }
}

@safe unittest
{
    SshBuffer b;
    NewKeys().serialize(b);
    ubyte[] expected = [21];
    assert(b.data == expected);
    assert(NewKeys.parse(b) == NewKeys());
}

@safe unittest
{
    auto m = Disconnect(11, "bye", "");
    SshBuffer b;
    m.serialize(b);
    assert(Disconnect.parse(b) == m);
}

@safe unittest
{
    auto m = ServiceAccept("ssh-userauth");
    SshBuffer b;
    m.serialize(b);
    assert(ServiceAccept.parse(b) == m);
}

@safe unittest
{
    ubyte[] qc = [1, 2, 3, 4];
    auto m = KexEcdhInit(qc);
    SshBuffer b;
    m.serialize(b);
    assert(KexEcdhInit.parse(b) == m);
}

@safe unittest
{
    ubyte[] ks = [0xaa];
    ubyte[] qs = [0xbb, 0xcc];
    ubyte[] sig = [0xdd];
    auto m = KexEcdhReply(ks, qs, sig);
    SshBuffer b;
    m.serialize(b);
    assert(KexEcdhReply.parse(b) == m);
}

/// SSH_MSG_USERAUTH_REQUEST with "publickey" method (RFC 4252 §7).
struct UserauthPublicKeyRequest
{
    string user;
    string service;
    string algorithm;
    const(ubyte)[] publicKeyBlob;
    const(ubyte)[] signature; // empty = probe without signature

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.userauthRequest);
        b.putStr(user);
        b.putStr(service);
        b.putStr("publickey");
        b.putBool(signature.length > 0);
        b.putStr(algorithm);
        b.putString(publicKeyBlob);
        if (signature.length > 0)
            b.putString(signature);
    }

    static UserauthPublicKeyRequest parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.userauthRequest);
        UserauthPublicKeyRequest m;
        m.user = b.readStr();
        m.service = b.readStr();
        if (b.readStr() != "publickey")
            throw new SshProtocolException("expected publickey method");
        const hasSignature = b.readBool();
        m.algorithm = b.readStr();
        m.publicKeyBlob = b.readString();
        if (hasSignature)
            m.signature = b.readString();
        return m;
    }
}

/// SSH_MSG_USERAUTH_FAILURE (RFC 4252 §5.1).
struct UserauthFailure
{
    string[] authenticationsThatCanContinue;
    bool partialSuccess;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.userauthFailure);
        b.putNameList(authenticationsThatCanContinue);
        b.putBool(partialSuccess);
    }

    static UserauthFailure parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.userauthFailure);
        UserauthFailure m;
        m.authenticationsThatCanContinue = b.readNameList();
        m.partialSuccess = b.readBool();
        return m;
    }
}

/// SSH_MSG_USERAUTH_SUCCESS (RFC 4252 §5.1).
struct UserauthSuccess
{
    void serialize(ref SshBuffer b) const @safe { b.putByte(SshMsg.userauthSuccess); }
    static UserauthSuccess parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.userauthSuccess);
        return UserauthSuccess();
    }
}

/// SSH_MSG_USERAUTH_BANNER (RFC 4252 §5.4).
struct UserauthBanner
{
    string message;
    string languageTag;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.userauthBanner);
        b.putStr(message);
        b.putStr(languageTag);
    }

    static UserauthBanner parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.userauthBanner);
        UserauthBanner m;
        m.message = b.readStr();
        m.languageTag = b.readStr();
        return m;
    }
}

@safe unittest
{
    ubyte[] blob = [0x01, 0x02];
    ubyte[] sig = [0x03];
    auto m = UserauthPublicKeyRequest("alice", "ssh-connection", "ssh-ed25519", blob, sig);
    SshBuffer b;
    m.serialize(b);
    assert(UserauthPublicKeyRequest.parse(b) == m);
}

@safe unittest
{
    ubyte[] blob = [0x01, 0x02];
    auto m = UserauthPublicKeyRequest("alice", "ssh-connection", "ssh-ed25519", blob, null);
    SshBuffer b;
    m.serialize(b);
    auto p = UserauthPublicKeyRequest.parse(b);
    assert(p == m);
    assert(p.signature.length == 0);
}

@safe unittest
{
    auto m = UserauthFailure(["publickey", "password"], false);
    SshBuffer b;
    m.serialize(b);
    assert(UserauthFailure.parse(b) == m);
}

@safe unittest
{
    SshBuffer b;
    UserauthSuccess().serialize(b);
    ubyte[] expected = [52];
    assert(b.data == expected);
    assert(UserauthSuccess.parse(b) == UserauthSuccess());
}

@safe unittest
{
    auto m = UserauthBanner("welcome", "en");
    SshBuffer b;
    m.serialize(b);
    assert(UserauthBanner.parse(b) == m);
}

/// SSH_MSG_CHANNEL_OPEN (RFC 4254 §5.1).
struct ChannelOpen
{
    string channelType;
    uint senderChannel;
    uint initialWindowSize;
    uint maximumPacketSize;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.channelOpen);
        b.putStr(channelType);
        b.putUint32(senderChannel);
        b.putUint32(initialWindowSize);
        b.putUint32(maximumPacketSize);
    }

    static ChannelOpen parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.channelOpen);
        ChannelOpen m;
        m.channelType = b.readStr();
        m.senderChannel = b.readUint32();
        m.initialWindowSize = b.readUint32();
        m.maximumPacketSize = b.readUint32();
        return m;
    }
}

/// SSH_MSG_CHANNEL_OPEN_CONFIRMATION (RFC 4254 §5.1).
struct ChannelOpenConfirmation
{
    uint recipientChannel;
    uint senderChannel;
    uint initialWindowSize;
    uint maximumPacketSize;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.channelOpenConfirmation);
        b.putUint32(recipientChannel);
        b.putUint32(senderChannel);
        b.putUint32(initialWindowSize);
        b.putUint32(maximumPacketSize);
    }

    static ChannelOpenConfirmation parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.channelOpenConfirmation);
        ChannelOpenConfirmation m;
        m.recipientChannel = b.readUint32();
        m.senderChannel = b.readUint32();
        m.initialWindowSize = b.readUint32();
        m.maximumPacketSize = b.readUint32();
        return m;
    }
}

/// SSH_MSG_CHANNEL_OPEN_FAILURE (RFC 4254 §5.1).
struct ChannelOpenFailure
{
    uint recipientChannel;
    uint reasonCode;
    string description;
    string languageTag;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.channelOpenFailure);
        b.putUint32(recipientChannel);
        b.putUint32(reasonCode);
        b.putStr(description);
        b.putStr(languageTag);
    }

    static ChannelOpenFailure parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.channelOpenFailure);
        ChannelOpenFailure m;
        m.recipientChannel = b.readUint32();
        m.reasonCode = b.readUint32();
        m.description = b.readStr();
        m.languageTag = b.readStr();
        return m;
    }
}

/// SSH_MSG_CHANNEL_WINDOW_ADJUST (RFC 4254 §5.2).
struct ChannelWindowAdjust
{
    uint recipientChannel;
    uint bytesToAdd;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.channelWindowAdjust);
        b.putUint32(recipientChannel);
        b.putUint32(bytesToAdd);
    }

    static ChannelWindowAdjust parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.channelWindowAdjust);
        ChannelWindowAdjust m;
        m.recipientChannel = b.readUint32();
        m.bytesToAdd = b.readUint32();
        return m;
    }
}

/// SSH_MSG_CHANNEL_EXTENDED_DATA (RFC 4254 §5.2).
struct ChannelExtendedData
{
    uint recipientChannel;
    uint dataTypeCode;
    const(ubyte)[] data;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.channelExtendedData);
        b.putUint32(recipientChannel);
        b.putUint32(dataTypeCode);
        b.putString(data);
    }

    static ChannelExtendedData parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.channelExtendedData);
        ChannelExtendedData m;
        m.recipientChannel = b.readUint32();
        m.dataTypeCode = b.readUint32();
        m.data = b.readString();
        return m;
    }
}

/// SSH_MSG_CHANNEL_EOF (RFC 4254 §5.3).
struct ChannelEof
{
    uint recipientChannel;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.channelEof);
        b.putUint32(recipientChannel);
    }

    static ChannelEof parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.channelEof);
        return ChannelEof(b.readUint32());
    }
}

/// SSH_MSG_CHANNEL_CLOSE (RFC 4254 §5.3).
struct ChannelClose
{
    uint recipientChannel;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.channelClose);
        b.putUint32(recipientChannel);
    }

    static ChannelClose parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.channelClose);
        return ChannelClose(b.readUint32());
    }
}

/// SSH_MSG_CHANNEL_REQUEST "exec" (RFC 4254 §6.5).
struct ChannelRequestExec
{
    uint recipientChannel;
    bool wantReply;
    string command;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.channelRequest);
        b.putUint32(recipientChannel);
        b.putStr("exec");
        b.putBool(wantReply);
        b.putStr(command);
    }

    static ChannelRequestExec parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.channelRequest);
        ChannelRequestExec m;
        m.recipientChannel = b.readUint32();
        if (b.readStr() != "exec")
            throw new SshProtocolException("expected exec request");
        m.wantReply = b.readBool();
        m.command = b.readStr();
        return m;
    }
}

/// SSH_MSG_CHANNEL_REQUEST "exit-status" (RFC 4254 §6.10).
struct ChannelRequestExitStatus
{
    uint recipientChannel;
    uint exitStatus;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.channelRequest);
        b.putUint32(recipientChannel);
        b.putStr("exit-status");
        b.putBool(false);
        b.putUint32(exitStatus);
    }

    static ChannelRequestExitStatus parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.channelRequest);
        ChannelRequestExitStatus m;
        m.recipientChannel = b.readUint32();
        if (b.readStr() != "exit-status")
            throw new SshProtocolException("expected exit-status request");
        b.readBool(); // want_reply, always false
        m.exitStatus = b.readUint32();
        return m;
    }
}

/// SSH_MSG_CHANNEL_REQUEST "exit-signal" (RFC 4254 §6.10).
struct ChannelRequestExitSignal
{
    uint recipientChannel;
    string signalName;
    bool coreDumped;
    string errorMessage;
    string languageTag;

    void serialize(ref SshBuffer b) const @safe
    {
        b.putByte(SshMsg.channelRequest);
        b.putUint32(recipientChannel);
        b.putStr("exit-signal");
        b.putBool(false);
        b.putStr(signalName);
        b.putBool(coreDumped);
        b.putStr(errorMessage);
        b.putStr(languageTag);
    }

    static ChannelRequestExitSignal parse(ref SshBuffer b) @safe
    {
        expectMsg(b, SshMsg.channelRequest);
        ChannelRequestExitSignal m;
        m.recipientChannel = b.readUint32();
        if (b.readStr() != "exit-signal")
            throw new SshProtocolException("expected exit-signal request");
        b.readBool(); // want_reply, always false
        m.signalName = b.readStr();
        m.coreDumped = b.readBool();
        m.errorMessage = b.readStr();
        m.languageTag = b.readStr();
        return m;
    }
}

@safe unittest
{
    auto m = ChannelOpen("session", 0, 2_097_152, 32_768);
    SshBuffer b; m.serialize(b);
    assert(ChannelOpen.parse(b) == m);
}

@safe unittest
{
    auto m = ChannelOpenConfirmation(0, 1, 2_097_152, 32_768);
    SshBuffer b; m.serialize(b);
    assert(ChannelOpenConfirmation.parse(b) == m);
}

@safe unittest
{
    auto m = ChannelOpenFailure(0, 4, "denied", "");
    SshBuffer b; m.serialize(b);
    assert(ChannelOpenFailure.parse(b) == m);
}

@safe unittest
{
    auto m = ChannelWindowAdjust(0, 4096);
    SshBuffer b; m.serialize(b);
    assert(ChannelWindowAdjust.parse(b) == m);
}

@safe unittest
{
    ubyte[] d = [0xee];
    auto m = ChannelExtendedData(0, 1, d);
    SshBuffer b; m.serialize(b);
    assert(ChannelExtendedData.parse(b) == m);
}

@safe unittest
{
    auto m = ChannelEof(3);
    SshBuffer b; m.serialize(b);
    assert(ChannelEof.parse(b) == m);
}

@safe unittest
{
    auto m = ChannelClose(3);
    SshBuffer b; m.serialize(b);
    assert(ChannelClose.parse(b) == m);
}

@safe unittest
{
    auto m = ChannelRequestExec(0, true, "uname -a");
    SshBuffer b; m.serialize(b);
    assert(ChannelRequestExec.parse(b) == m);
}

@safe unittest
{
    auto m = ChannelRequestExitStatus(0, 0);
    SshBuffer b; m.serialize(b);
    assert(ChannelRequestExitStatus.parse(b) == m);
}

@safe unittest
{
    auto m = ChannelRequestExitSignal(0, "TERM", false, "killed", "");
    SshBuffer b; m.serialize(b);
    assert(ChannelRequestExitSignal.parse(b) == m);
}

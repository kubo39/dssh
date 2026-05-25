/// vibe-core adapter: sync-looking client facade.
module dssh.vibe.client;

import vibe.core.net : TCPConnection, connectTCP;
import vibe.core.core : runTask;
import vibe.core.task : Task;
import vibe.core.sync : TaskMutex, TaskCondition;
import vibe.core.stream : IOMode;

import dssh;

/// Primary entry point; delegates to SshClient.connect.
SshClient connectSSH(string host, ushort port, SshConfig cfg)
{
    return SshClient.connect(host, port, cfg);
}

final class SshClient
{
    private TCPConnection conn;
    private Task pumpTask;
    private ProtocolCore core;
    private SshChannel[uint] channels;
    private bool serviceRequested;
    private bool closed;

    private TaskMutex stateMutex;   // guards incoming/fatal/pumpDone; backs `signal`
    private TaskCondition signal;   // pump notifies on new events / handshake progress / exit
    private TaskMutex writeMutex;   // serializes conn.write across the pump and callers
    private ubyte[][] incoming;     // decrypted application payloads queued by the pump
    private Exception fatal;        // set by the pump on a read/protocol failure
    private bool pumpDone;          // the pump loop has exited

    static SshClient connect(string host, ushort port, SshConfig cfg)
    {
        auto c = new SshClient();
        c.stateMutex = new TaskMutex;
        c.signal = new TaskCondition(c.stateMutex);
        c.writeMutex = new TaskMutex;
        c.conn = connectTCP(host, port);
        c.core = ProtocolCore(cfg, host, port);
        c.core.start();
        c.flush();                         // send our banner + KEXINIT
        c.pumpTask = runTask(&c.pumpLoop); // the pump drives the handshake from here on

        synchronized (c.stateMutex)
            while (!c.core.transportEstablished() && c.fatal is null && !c.pumpDone)
                c.signal.wait();
        if (c.fatal !is null)
            throw c.fatal;
        if (!c.core.transportEstablished())
            throw new SshConnectException("connection closed during handshake");
        return c;
    }

    /// Whether the transport handshake (banner + KEX + NEW_KEYS) is complete.
    bool transportEstablished() const { return core.transportEstablished(); }

    // Background fiber: read the socket, advance the protocol, queue decrypted events.
    private void pumpLoop() nothrow
    {
        ubyte[4096] buf;
        try
        {
            for (;;)
            {
                const n = conn.read(buf[], IOMode.once);
                if (n == 0)
                    break; // peer closed the connection
                core.feedIncoming(buf[0 .. n]);
                auto events = core.takeEvents();
                synchronized (stateMutex)
                {
                    if (events.length)
                        incoming ~= events;
                    signal.notifyAll(); // wake the handshake waiter and recvPacket
                }
                flush(); // push KEX/rekey responses and anything sendPacket queued
            }
        }
        catch (Exception e)
        {
            try
                synchronized (stateMutex) { if (fatal is null) fatal = e; }
            catch (Exception)
            {
            }
        }
        try
        {
            synchronized (stateMutex) pumpDone = true;
            signal.notifyAll();
        }
        catch (Exception)
        {
        }
    }

    private void flush()
    {
        synchronized (writeMutex)
        {
            auto outgoing = core.takeOutgoing();
            if (outgoing.length)
                conn.write(outgoing);
        }
    }

    /// Try each method in order until one succeeds; returns the last result otherwise.
    AuthResult authenticate(string user, AuthMethod[] methods)
    {
        AuthResult last;
        foreach (ref m; methods)
        {
            last = tryAuth(user, m);
            if (last.success)
                return last;
        }
        return last;
    }

    AuthResult tryAuth(string user, const ref AuthMethod method)
    {
        if (!serviceRequested)
        {
            SshBuffer sr;
            sr.putByte(SshMsg.serviceRequest);
            sr.putStr("ssh-userauth");
            core.sendPacket(sr.data);
            flush();
            auto accept = recvPacket();
            if (accept.length == 0 || accept[0] != SshMsg.serviceAccept)
                throw new SshProtocolException("expected SERVICE_ACCEPT");
            serviceRequested = true;
        }

        core.sendPacket(buildAuthRequest(method, core.sessionId, user, "ssh-connection"));
        flush();

        for (;;)
        {
            auto resp = recvPacket();
            if (resp.length == 0)
                throw new SshProtocolException("empty auth response");
            switch (cast(SshMsg) resp[0])
            {
            case SshMsg.userauthSuccess:
                return AuthResult(true);
            case SshMsg.userauthFailure:
                auto fb = SshBuffer(resp);
                auto f = UserauthFailure.parse(fb);
                return AuthResult(false, f.partialSuccess, f.authenticationsThatCanContinue);
            case SshMsg.userauthBanner:
                continue; // informational
            default:
                throw new SshProtocolException("unexpected auth response");
            }
        }
    }

    // Wait for the next decrypted application payload delivered by the pump.
    private const(ubyte)[] recvPacket()
    {
        synchronized (stateMutex)
        {
            while (incoming.length == 0 && fatal is null && !pumpDone)
                signal.wait();
            if (incoming.length)
            {
                auto p = incoming[0];
                incoming = incoming[1 .. $];
                return p;
            }
        }
        if (fatal !is null)
            throw fatal;
        throw new SshConnectException("connection closed");
    }

    SshChannel exec(string) { assert(0, "TODO: streaming channel"); }

    /// Open a session channel, run a command, and collect stdout/stderr/exit status.
    CommandResult run(string command)
    {
        enum uint localChannel = 0;
        enum uint window = 2 * 1024 * 1024;
        enum uint maxPacket = 32 * 1024;

        SshBuffer ob;
        ChannelOpen("session", localChannel, window, maxPacket).serialize(ob);
        core.sendPacket(ob.data);
        flush();

        uint remoteChannel;
        for (;;)
        {
            auto p = recvPacket();
            const m = cast(SshMsg) p[0];
            if (m == SshMsg.channelOpenConfirmation)
            {
                auto cb = SshBuffer(p);
                remoteChannel = ChannelOpenConfirmation.parse(cb).senderChannel;
                break;
            }
            if (m == SshMsg.channelOpenFailure)
            {
                auto cb = SshBuffer(p);
                throw new SshChannelException("channel open failed: " ~ ChannelOpenFailure.parse(cb).description);
            }
            // ignore unrelated control messages (e.g. GLOBAL_REQUEST)
        }

        SshBuffer eb;
        ChannelRequestExec(remoteChannel, false, command).serialize(eb);
        core.sendPacket(eb.data);
        flush();

        CommandResult result;
        bool channelClosed;
        while (!channelClosed)
        {
            auto p = recvPacket();
            switch (cast(SshMsg) p[0])
            {
            case SshMsg.channelData:
                auto cb = SshBuffer(p);
                auto d = ChannelData.parse(cb);
                result.stdout ~= d.data;
                adjustWindow(remoteChannel, cast(uint) d.data.length);
                break;
            case SshMsg.channelExtendedData:
                auto cb = SshBuffer(p);
                auto d = ChannelExtendedData.parse(cb);
                if (d.dataTypeCode == SshExtendedDataType.stderr)
                    result.stderr ~= d.data;
                adjustWindow(remoteChannel, cast(uint) d.data.length);
                break;
            case SshMsg.channelRequest:
                parseChannelRequest(p, result);
                break;
            case SshMsg.channelClose:
                channelClosed = true;
                break;
            default:
                break; // EOF, window adjust, global requests, etc.
            }
        }

        SshBuffer cb;
        ChannelClose(remoteChannel).serialize(cb);
        core.sendPacket(cb.data);
        flush();
        return result;
    }

    private void adjustWindow(uint channel, uint bytes)
    {
        if (bytes == 0)
            return;
        SshBuffer b;
        ChannelWindowAdjust(channel, bytes).serialize(b);
        core.sendPacket(b.data);
        flush();
    }

    private static void parseChannelRequest(const(ubyte)[] payload, ref CommandResult result)
    {
        auto b = SshBuffer(payload);
        b.readByte();   // message type
        b.readUint32(); // recipient channel
        const reqType = b.readStr();
        b.readBool();   // want_reply
        if (reqType == "exit-status")
        {
            result.status.exited = true;
            result.status.code = cast(int) b.readUint32();
        }
        else if (reqType == "exit-signal")
        {
            result.status.signaled = true;
            result.status.signal = b.readStr();
            result.status.coreDumped = b.readBool();
            result.status.errorMsg = b.readStr();
        }
    }

    /// Send SSH_MSG_DISCONNECT, close the socket, stop the pump, and destroy the core.
    void close()
    {
        if (closed)
            return;
        closed = true;
        try
        {
            SshBuffer b;
            Disconnect(11, "shutting down", "").serialize(b); // SSH_DISCONNECT_BY_APPLICATION
            core.sendPacket(b.data);
            flush();
        }
        catch (Exception)
        {
        }
        try
            conn.close();
        catch (Exception)
        {
        }
        // Let the pump observe the closed socket and exit before the core is destroyed
        // (the pump touches core in feedIncoming/takeOutgoing).
        try
            pumpTask.join();
        catch (Exception)
        {
        }
        destroy(core);
    }
}

final class SshChannel
{
    private ubyte[] inboundBuffer;
    private ubyte[] stderrBuffer;
    private bool eof_;
    private TaskMutex mutex;
    private TaskCondition dataOrEof;

    void write(const(ubyte)[]) { assert(0, "TODO"); }
    void closeStdin()          { assert(0, "TODO"); }

    ubyte[] read(size_t = size_t.max)       { assert(0, "TODO"); }
    ubyte[] readStderr(size_t = size_t.max) { assert(0, "TODO"); }
    ubyte[] readAll()                       { assert(0, "TODO"); }
    bool eof() const { return eof_; }

    ExitStatus waitExit() { assert(0, "TODO"); }
    void close()          { assert(0, "TODO"); }
}

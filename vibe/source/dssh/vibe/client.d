/// vibe-core adapter: sync-looking client facade.
module dssh.vibe.client;

import vibe.core.net : TCPConnection, connectTCP;
import vibe.core.core : runTask;
import vibe.core.task : Task;
import vibe.core.sync : TaskMutex, TaskCondition;
import vibe.core.stream : IOMode;

import dssh;

private enum uint channelInitialWindow = 2 * 1024 * 1024;
private enum uint channelMaxPacket = 32 * 1024;

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
    private uint nextChannelId;
    private bool serviceRequested;
    private bool closed;

    private TaskMutex stateMutex;   // guards incoming/fatal/pumpDone + all channel state; backs `signal`
    private TaskCondition signal;   // pump notifies on new events / handshake progress / exit
    private TaskMutex writeMutex;   // serializes conn.write across the pump and callers
    private const(ubyte)[][] incoming; // non-channel app payloads queued by the pump (auth, global)
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

    // Background fiber: read the socket, advance the protocol, route decrypted events.
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
                {
                    // `synchronized` is not nothrow (_d_monitorenter); TaskMutex.lock is, and
                    // takes the same underlying lock, so it interoperates with synchronized.
                    stateMutex.lock();
                    scope (exit) stateMutex.unlock();
                    foreach (ev; events)
                        routeEvent(ev);
                    signal.notifyAll(); // wake the handshake waiter, recvPacket, and channels
                }
                flush(); // push KEX/rekey responses and anything sendPacket queued
            }
        }
        catch (Exception e)
        {
            // Surface the failure to everyone waiting on `signal`.
            stateMutex.lock();
            scope (exit) stateMutex.unlock();
            if (fatal is null)
                fatal = e;
        }
        {
            stateMutex.lock();
            scope (exit) stateMutex.unlock();
            pumpDone = true;
        }
        signal.notifyAll();
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

    // Called under stateMutex (no yield). Channel messages go to their SshChannel;
    // everything else (auth responses, global requests) is queued for recvPacket.
    private SshChannel chan(uint id) { return channels.get(id, null); }

    private void routeEvent(const(ubyte)[] ev)
    {
        if (ev.length == 0)
            return;
        auto b = SshBuffer(ev);
        switch (cast(SshMsg) ev[0])
        {
        case SshMsg.channelOpenConfirmation:
            auto m = ChannelOpenConfirmation.parse(b);
            if (auto ch = chan(m.recipientChannel))
                ch.onOpenConfirm(m.senderChannel, m.initialWindowSize, m.maximumPacketSize);
            break;
        case SshMsg.channelOpenFailure:
            auto m = ChannelOpenFailure.parse(b);
            if (auto ch = chan(m.recipientChannel))
                ch.onOpenFailure(m.description);
            break;
        case SshMsg.channelData:
            auto m = ChannelData.parse(b);
            if (auto ch = chan(m.recipientChannel))
                ch.onData(m.data);
            break;
        case SshMsg.channelExtendedData:
            auto m = ChannelExtendedData.parse(b);
            if (auto ch = chan(m.recipientChannel))
                ch.onExtended(m.dataTypeCode, m.data);
            break;
        case SshMsg.channelWindowAdjust:
            auto m = ChannelWindowAdjust.parse(b);
            if (auto ch = chan(m.recipientChannel))
                ch.onWindowAdjust(m.bytesToAdd);
            break;
        case SshMsg.channelEof:
            auto m = ChannelEof.parse(b);
            if (auto ch = chan(m.recipientChannel))
                ch.onEof();
            break;
        case SshMsg.channelClose:
            auto m = ChannelClose.parse(b);
            if (auto ch = chan(m.recipientChannel))
                ch.onClose();
            break;
        case SshMsg.channelRequest:
            routeChannelRequest(ev);
            break;
        case SshMsg.channelSuccess:
        case SshMsg.channelFailure:
            break; // replies to our channel requests; not awaited yet
        default:
            incoming ~= ev; // auth, global requests, etc.
        }
    }

    private void routeChannelRequest(const(ubyte)[] ev)
    {
        auto b = SshBuffer(ev);
        b.readByte();
        auto ch = chan(b.readUint32());
        if (ch is null)
            return;
        const reqType = b.readStr();
        b.readBool(); // want_reply
        if (reqType == "exit-status")
            ch.onExitStatus(cast(int) b.readUint32());
        else if (reqType == "exit-signal")
            ch.onExitSignal(b.readStr(), b.readBool(), b.readStr());
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

    // Wait for the next non-channel application payload delivered by the pump.
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

    /// Open a session channel and start a command; returns a streaming channel.
    SshChannel exec(string command)
    {
        auto ch = openSession();
        SshBuffer eb;
        ChannelRequestExec(ch.remoteId, wantReply: false, command: command).serialize(eb);
        core.sendPacket(eb.data);
        flush();
        return ch;
    }

    /// Open a session channel with a pseudo-terminal and start the login shell.
    SshChannel shell(string term = "xterm-256color", uint cols = 80, uint rows = 24)
    {
        auto ch = openSession();
        SshBuffer pb;
        ChannelRequestPtyReq(ch.remoteId, wantReply: false, term: term,
            widthChars: cols, heightRows: rows, widthPixels: 0, heightPixels: 0,
            terminalModes: [cast(ubyte) 0]).serialize(pb);
        core.sendPacket(pb.data);
        SshBuffer sb;
        ChannelRequestShell(ch.remoteId, wantReply: false).serialize(sb);
        core.sendPacket(sb.data);
        flush();
        return ch;
    }

    /// Open a session channel, run a command, and collect stdout/stderr/exit status.
    CommandResult run(string command)
    {
        auto ch = exec(command);
        scope (exit)
            ch.close();

        CommandResult result;
        for (;;)
        {
            size_t consumed;
            bool done;
            synchronized (stateMutex)
            {
                while (ch.stdoutBuf.length == 0 && ch.stderrBuf.length == 0
                       && !ch.closeReceived && fatal is null)
                    signal.wait();
                if (fatal !is null)
                    throw fatal;
                if (ch.stdoutBuf.length)
                {
                    result.stdout ~= ch.stdoutBuf;
                    consumed += ch.stdoutBuf.length;
                    ch.stdoutBuf = null;
                }
                if (ch.stderrBuf.length)
                {
                    result.stderr ~= ch.stderrBuf;
                    consumed += ch.stderrBuf.length;
                    ch.stderrBuf = null;
                }
                done = ch.closeReceived && ch.stdoutBuf.length == 0 && ch.stderrBuf.length == 0;
                if (done)
                    result.status = ch.exitStatus_;
            }
            if (consumed)
                ch.sendWindowAdjust(consumed);
            if (done)
                break;
        }
        return result;
    }

    private SshChannel openSession()
    {
        uint localId;
        SshChannel ch;
        synchronized (stateMutex)
        {
            localId = nextChannelId++;
            ch = new SshChannel(this, localId);
            channels[localId] = ch;
        }

        SshBuffer ob;
        ChannelOpen("session", localId, channelInitialWindow, channelMaxPacket).serialize(ob);
        core.sendPacket(ob.data);
        flush();

        synchronized (stateMutex)
        {
            while (!ch.opened && !ch.openFailed && fatal is null)
                signal.wait();
            if (fatal !is null)
                throw fatal;
            if (ch.openFailed)
            {
                channels.remove(localId);
                throw new SshChannelException("channel open failed: " ~ ch.openFailReason);
            }
        }
        return ch;
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

/// A session channel. Data is delivered by the client's pump into per-channel buffers;
/// reads/writes block on the client's condition. Flow control is the SSH window
/// (not queue back-pressure), so the pump never blocks delivering here.
final class SshChannel
{
    private SshClient client;
    private uint localId;
    private uint remoteId;          // peer's channel number (recipient of our messages)
    private uint remoteWindow;      // bytes we may still send to the peer
    private uint remoteMaxPacket;
    private ubyte[] stdoutBuf;
    private ubyte[] stderrBuf;
    private bool opened, openFailed;
    private string openFailReason;
    private bool eofReceived, closeReceived;
    private bool exited;
    private ExitStatus exitStatus_;
    private bool closeSent;

    private this(SshClient client, uint localId)
    {
        this.client = client;
        this.localId = localId;
    }

    // ---- pump side: called under client.stateMutex; the pump notifies once afterward ----
    private void onOpenConfirm(uint sender, uint window, uint maxPkt)
    {
        remoteId = sender;
        remoteWindow = window;
        remoteMaxPacket = maxPkt;
        opened = true;
    }
    private void onOpenFailure(string reason) { openFailReason = reason; openFailed = true; }
    private void onData(const(ubyte)[] d) { stdoutBuf ~= d; }
    private void onExtended(uint typeCode, const(ubyte)[] d)
    {
        if (typeCode == SshExtendedDataType.stderr)
            stderrBuf ~= d;
    }
    private void onWindowAdjust(uint n) { remoteWindow += n; }
    private void onEof() { eofReceived = true; }
    private void onClose() { closeReceived = true; }
    private void onExitStatus(int code)
    {
        exitStatus_.exited = true;
        exitStatus_.code = code;
        exited = true;
    }
    private void onExitSignal(string sig, bool coreDumped, string msg)
    {
        exitStatus_.signaled = true;
        exitStatus_.signal = sig;
        exitStatus_.coreDumped = coreDumped;
        exitStatus_.errorMsg = msg;
        exited = true;
    }

    // ---- user side: acquire client.stateMutex; send packets outside the lock ----

    /// Write to the command's stdin, respecting the peer's window.
    void write(const(ubyte)[] data)
    {
        while (data.length)
        {
            uint n;
            synchronized (client.stateMutex)
            {
                while (remoteWindow == 0 && !closeReceived && client.fatal is null)
                    client.signal.wait();
                if (client.fatal !is null)
                    throw client.fatal;
                if (closeReceived)
                    throw new SshChannelException("channel closed");
                const limit = remoteWindow < remoteMaxPacket ? remoteWindow : remoteMaxPacket;
                n = cast(uint)(data.length < limit ? data.length : limit);
                remoteWindow -= n;
            }
            SshBuffer b;
            ChannelData(remoteId, data[0 .. n]).serialize(b);
            client.core.sendPacket(b.data);
            client.flush();
            data = data[n .. $];
        }
    }

    /// Signal stdin EOF (CHANNEL_EOF).
    void closeStdin()
    {
        SshBuffer b;
        ChannelEof(remoteId).serialize(b);
        client.core.sendPacket(b.data);
        client.flush();
    }

    /// Tell the peer the terminal dimensions changed (only meaningful with a pty).
    void windowChange(uint cols, uint rows)
    {
        SshBuffer b;
        ChannelRequestWindowChange(remoteId, cols, rows, 0, 0).serialize(b);
        client.core.sendPacket(b.data);
        client.flush();
    }

    /// Read up to `max` stdout bytes; empty result means EOF/close.
    ubyte[] read(size_t max = size_t.max) { return readFrom(false, max); }

    /// Read up to `max` stderr bytes; empty result means EOF/close.
    ubyte[] readStderr(size_t max = size_t.max) { return readFrom(true, max); }

    private ubyte[] readFrom(bool stderr, size_t max)
    {
        ubyte[] chunk;
        size_t consumed;
        synchronized (client.stateMutex)
        {
            auto buf() { return stderr ? &stderrBuf : &stdoutBuf; }
            while (buf().length == 0 && !eofReceived && !closeReceived && client.fatal is null)
                client.signal.wait();
            if (client.fatal !is null)
                throw client.fatal;
            const avail = buf().length;
            const n = max < avail ? max : avail;
            chunk = (*buf())[0 .. n].dup;
            *buf() = (*buf())[n .. $];
            consumed = n;
        }
        if (consumed)
            sendWindowAdjust(consumed);
        return chunk;
    }

    /// Read stdout until EOF/close.
    ubyte[] readAll()
    {
        ubyte[] all;
        for (;;)
        {
            auto c = read();
            if (c.length == 0)
                break;
            all ~= c;
        }
        return all;
    }

    bool eof() const { return eofReceived; }

    /// Wait for the command to exit; returns its status.
    ExitStatus waitExit()
    {
        synchronized (client.stateMutex)
        {
            while (!exited && !closeReceived && client.fatal is null)
                client.signal.wait();
            if (client.fatal !is null)
                throw client.fatal;
            return exitStatus_;
        }
    }

    /// Send CHANNEL_CLOSE (idempotent).
    void close()
    {
        synchronized (client.stateMutex)
        {
            if (closeSent)
                return;
            closeSent = true;
        }
        try
        {
            SshBuffer b;
            ChannelClose(remoteId).serialize(b);
            client.core.sendPacket(b.data);
            client.flush();
        }
        catch (Exception)
        {
        }
    }

    // Replenish the peer's send window by the number of bytes we consumed.
    private void sendWindowAdjust(size_t n)
    {
        SshBuffer b;
        ChannelWindowAdjust(remoteId, cast(uint) n).serialize(b);
        client.core.sendPacket(b.data);
        client.flush();
    }
}

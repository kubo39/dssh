import std.conv : to;
import std.stdio : writeln;
import vibe.core.core : runTask, runEventLoop, exitEventLoop;
import dssh.vibe;

int main(string[] args)
{
    immutable port = args.length > 1 ? args[1].to!ushort : ushort(2022);
    immutable user = args.length > 2 ? args[2] : "tester";
    immutable keyPath = args.length > 3 ? args[3] : "/tmp/dssh_testkey";
    immutable knownHostsPath = args.length > 4 ? args[4] : "";
    int rc = 1;

    runTask(() nothrow {
        scope (exit)
            exitEventLoop();
        string msg = "FAIL";
        try
        {
            // Verify the server host key against known_hosts when a file is given; otherwise
            // (standalone runs) fall back to the insecure, test-only verifier.
            auto verifier = knownHostsPath.length ? knownHosts(knownHostsPath) : insecureAcceptAll();
            auto cfg = SshConfig(hostKeyVerifier: verifier);
            auto sess = connectSSH("127.0.0.1", port, cfg);
            scope (exit)
                sess.close();
            auto result = sess.authenticate(user, [publicKey(loadPrivateKey(keyPath))]);
            if (!result.success)
                msg = "FAIL: authentication rejected by server";
            else
            {
                immutable how = knownHostsPath.length ? "known_hosts-verified " : "";

                // 1) run(): buffered command, collect stdout + exit status.
                auto cmd = sess.run("echo hello-from-dssh");
                immutable runOut = cast(string) cmd.stdout;
                immutable runOk = runOut == "hello-from-dssh\n" && cmd.status.exited && cmd.status.code == 0;

                // 2) streaming exec(): write to stdin and read it back through `cat`.
                auto ch = sess.exec("cat");
                ch.write(cast(const(ubyte)[]) "stream-payload\n");
                ch.closeStdin();
                immutable echoed = cast(string) ch.readAll();
                immutable st = ch.waitExit();
                ch.close();
                immutable streamOk = echoed == "stream-payload\n" && st.exited && st.code == 0;

                // 3) shell() with a pty: drive an interactive login shell.
                import std.string : indexOf;
                auto sh = sess.shell("vt100", 80, 24);
                sh.write(cast(const(ubyte)[]) "echo shell-pty-ok; exit\n");
                immutable shellOut = cast(string) sh.readAll();
                immutable shExit = sh.waitExit();
                sh.close();
                immutable shellOk = shellOut.indexOf("shell-pty-ok") >= 0 && shExit.exited;

                if (runOk && streamOk && shellOk)
                {
                    msg = "OK: " ~ how ~ "transport + publickey auth + run() + streaming exec + pty shell";
                    rc = 0;
                }
                else
                    msg = "FAIL: run[" ~ runOut ~ "/" ~ cmd.status.code.to!string
                        ~ "] stream[" ~ echoed ~ "/" ~ st.code.to!string
                        ~ "] shell[" ~ (shellOk ? "ok" : "bad") ~ "]";
            }
        }
        catch (Exception e)
            msg = "ERROR: " ~ e.msg;
        try
            writeln(msg);
        catch (Exception)
        {
        }
    });

    runEventLoop();
    return rc;
}

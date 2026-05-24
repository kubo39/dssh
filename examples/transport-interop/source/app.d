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
                auto cmd = sess.run("echo hello-from-dssh");
                immutable stdout_ = cast(string) cmd.stdout;
                if (stdout_ == "hello-from-dssh\n" && cmd.status.exited && cmd.status.code == 0)
                {
                    immutable how = knownHostsPath.length ? "known_hosts-verified " : "";
                    msg = "OK: " ~ how ~ "transport + publickey auth + exec (stdout matched, exit 0)";
                    rc = 0;
                }
                else
                    msg = "FAIL: exec stdout=[" ~ stdout_ ~ "] exit=" ~ cmd.status.code.to!string;
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

/// Channel data types. The SshChannel class lives in the vibe layer.
module dssh.channel;

/// Holds both exit-status and exit-signal outcomes.
struct ExitStatus
{
    bool exited;
    int code;
    bool signaled;
    string signal;
    bool coreDumped;
    string errorMsg;
}

struct CommandResult
{
    ubyte[] stdout;
    ubyte[] stderr;
    ExitStatus status;
}

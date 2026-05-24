/// SSH exception hierarchy.
module dssh.exception;

private mixin template SshExceptionCtor()
{
    this(string msg, string file = __FILE__, size_t line = __LINE__) nothrow @safe
    {
        super(msg, file, line);
    }
}

class SshException : Exception { mixin SshExceptionCtor; }
class SshConnectException : SshException { mixin SshExceptionCtor; }
class SshProtocolException : SshException { mixin SshExceptionCtor; }
class SshDisconnectException : SshException { mixin SshExceptionCtor; }
class SshChannelException : SshException { mixin SshExceptionCtor; }
class SshHostKeyException : SshConnectException { mixin SshExceptionCtor; }
class SshAuthException : SshException { mixin SshExceptionCtor; }

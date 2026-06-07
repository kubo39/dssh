/// SSH exception hierarchy.
module dssh.exception;

import std.exception : basicExceptionCtors;

class SshException : Exception { mixin basicExceptionCtors; }
class SshConnectException : SshException { mixin basicExceptionCtors; }
class SshProtocolException : SshException { mixin basicExceptionCtors; }
class SshDisconnectException : SshException { mixin basicExceptionCtors; }
class SshChannelException : SshException { mixin basicExceptionCtors; }
class SshHostKeyException : SshConnectException { mixin basicExceptionCtors; }
class SshAuthException : SshException { mixin basicExceptionCtors; }

/// Connection config.
module dssh.config;

import core.time : Duration, seconds, hours;
import dssh.hostkey : HostKeyVerifier;

/// Algorithm preferences as ordered name-lists.
struct Algorithms
{
    string[] kex = ["curve25519-sha256"];
    string[] hostKey = ["ssh-ed25519"];
    string[] cipher = ["aes256-gcm@openssh.com"];
    string[] mac = [];
    string[] compression = ["none"];
}

struct SshConfig
{
    string clientVersion = "SSH-2.0-dssh_0.1";
    Duration connectTimeout = 30.seconds;

    /// Required: if null, connectSSH fails closed with SshConnectException.
    HostKeyVerifier hostKeyVerifier;

    Algorithms algorithms;

    ulong rekeyBytes = 1UL << 30;
    Duration rekeyInterval = 1.hours;

    Duration keepaliveInterval = Duration.zero;
    uint windowSize = 2 * 1024 * 1024;
    uint maxPacketSize = 32 * 1024;
}

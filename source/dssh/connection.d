/// Upper-layer state machine (RFC 4252/4254). Default .init = AwaitingTransport.
module dssh.connection;

import std.sumtype : SumType;

struct AwaitingTransport {}
struct ServiceRequest {}
struct UserAuth {}
struct Active {}
struct Closed
{
    uint reasonCode;
    string description;
}

alias UpperState = SumType!(AwaitingTransport, ServiceRequest, UserAuth, Active, Closed);

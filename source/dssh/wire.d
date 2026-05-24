/// SSH wire format: cursor + per-type API.
module dssh.wire;

import std.bigint : BigInt;
import std.bitmanip : nativeToBigEndian, bigEndianToNative;
import dssh.exception : SshProtocolException;

struct SshBuffer
{
    const(ubyte)[] data;
    size_t pos;

@safe:

    private void need(size_t n)
    {
        if (data.length - pos < n)
            throw new SshProtocolException("truncated SSH message");
    }

    // Reads throw SshProtocolException on short/invalid input.
    ubyte readByte()
    {
        need(1);
        return data[pos++];
    }

    const(ubyte)[] readRaw(size_t n)
    {
        need(n);
        auto s = data[pos .. pos + n];
        pos += n;
        return s;
    }

    uint readUint32()
    {
        need(4);
        ubyte[4] tmp = data[pos .. pos + 4];
        pos += 4;
        return bigEndianToNative!uint(tmp);
    }

    ulong readUint64()
    {
        need(8);
        ubyte[8] tmp = data[pos .. pos + 8];
        pos += 8;
        return bigEndianToNative!ulong(tmp);
    }

    bool readBool() { return readByte() != 0; }

    const(ubyte)[] readString()
    {
        const len = readUint32();
        need(len);
        auto s = data[pos .. pos + len];
        pos += len;
        return s;
    }

    /// Like readString, but for textual fields. Returns an independent copy.
    string readStr() { return cast(string) readString().idup; }

    string[] readNameList()
    {
        import std.array : split;
        auto raw = readString();
        if (raw.length == 0)
            return [];
        return (cast(string) raw.idup).split(",");
    }

    BigInt readMpint()
    {
        auto raw = readString();
        if (raw.length == 0)
            return BigInt(0);
        if (raw[0] & 0x80)
            throw new SshProtocolException("negative mpint not supported");
        return BigInt(false, raw); // big-endian magnitude, always non-negative here
    }

    void putByte(ubyte v)                  { data ~= v; }
    void putRaw(const(ubyte)[] s)          { data ~= s; }
    void putUint32(uint v)                 { data ~= nativeToBigEndian(v)[]; }
    void putUint64(ulong v)                { data ~= nativeToBigEndian(v)[]; }
    void putBool(bool v)                   { data ~= cast(ubyte)(v ? 1 : 0); }
    void putString(const(ubyte)[] s)
    {
        putUint32(cast(uint) s.length);
        data ~= s;
    }

    void putStr(string s) { putString(cast(const(ubyte)[]) s); }

    void putNameList(const(string)[] names)
    {
        import std.array : join;
        putString(cast(const(ubyte)[]) names.join(","));
    }

    void putMpint(BigInt n)
    {
        import std.algorithm.mutation : reverse;

        if (n < 0)
            throw new SshProtocolException("negative mpint not supported");
        if (n == 0)
            return putUint32(0);

        ubyte[] bytes;
        for (BigInt t = n; t > 0; t >>= 8)
            bytes ~= cast(ubyte)((t & 0xff).toLong());
        bytes.reverse();
        if (bytes[0] & 0x80)
            bytes = ubyte(0) ~ bytes;
        putString(bytes);
    }

    /// Encode a non-negative big-endian magnitude as mpint directly, without a BigInt
    /// round-trip. Strips leading zero bytes and prepends 0x00 if the top bit is set.
    void putMpint(const(ubyte)[] magnitude)
    {
        size_t i = 0;
        while (i < magnitude.length && magnitude[i] == 0)
            i++;
        auto m = magnitude[i .. $];
        if (m.length == 0)
            return putUint32(0);
        if (m[0] & 0x80)
        {
            putUint32(cast(uint)(m.length + 1));
            putByte(0);
            putRaw(m);
        }
        else
            putString(m);
    }
}

@safe unittest
{
    SshBuffer b;
    b.putUint32(0x01020304);
    ubyte[] expected = [1, 2, 3, 4];
    assert(b.data == expected);
}

@safe unittest
{
    ubyte[] src = [1, 2, 3, 4];
    auto b = SshBuffer(src);
    assert(b.readUint32() == 0x01020304);
    assert(b.pos == 4);
}

@safe unittest
{
    import std.exception : assertThrown;
    ubyte[] src = [1, 2];
    auto b = SshBuffer(src);
    assertThrown!SshProtocolException(b.readUint32());
}

@safe unittest
{
    SshBuffer w;
    w.putByte(0x42);
    ubyte[] expected = [0x42];
    assert(w.data == expected);

    auto r = SshBuffer(expected);
    assert(r.readByte() == 0x42);
    assert(r.pos == 1);
}

@safe unittest
{
    SshBuffer w;
    w.putUint64(0x0102030405060708);
    ubyte[] expected = [1, 2, 3, 4, 5, 6, 7, 8];
    assert(w.data == expected);

    auto r = SshBuffer(expected);
    assert(r.readUint64() == 0x0102030405060708);
    assert(r.pos == 8);
}

@safe unittest
{
    SshBuffer w;
    w.putBool(true);
    w.putBool(false);
    ubyte[] expected = [1, 0];
    assert(w.data == expected);

    auto r = SshBuffer(expected);
    assert(r.readBool() == true);
    assert(r.readBool() == false);

    ubyte[] nz = [0xff];
    assert(SshBuffer(nz).readBool() == true);
}

@safe unittest
{
    SshBuffer w;
    ubyte[] payload = [0xde, 0xad, 0xbe, 0xef];
    w.putString(payload);
    ubyte[] expected = [0, 0, 0, 4, 0xde, 0xad, 0xbe, 0xef];
    assert(w.data == expected);

    auto r = SshBuffer(expected);
    assert(r.readString() == payload);
    assert(r.pos == 8);
}

@safe unittest
{
    import std.exception : assertThrown;
    ubyte[] bad = [0, 0, 0, 9, 1, 2];
    assertThrown!SshProtocolException(SshBuffer(bad).readString());
}

@safe unittest
{
    SshBuffer w;
    string[] names = ["ssh-ed25519", "rsa-sha2-256"];
    w.putNameList(names);
    assert(SshBuffer(w.data).readNameList() == names);
}

@safe unittest
{
    SshBuffer w;
    string[] empty;
    w.putNameList(empty);
    ubyte[] expected = [0, 0, 0, 0];
    assert(w.data == expected);
    assert(SshBuffer(expected).readNameList().length == 0);
}

@safe unittest // RFC 4251 mpint vectors
{
    void roundtrip(BigInt v, ubyte[] enc)
    {
        SshBuffer w;
        w.putMpint(v);
        assert(w.data == enc);
        assert(SshBuffer(enc).readMpint() == v);
    }

    roundtrip(BigInt(0), [0, 0, 0, 0]);
    roundtrip(BigInt(0x80), [0, 0, 0, 2, 0x00, 0x80]);
    roundtrip(BigInt("0x9a378f9b2e332a7"),
              [0, 0, 0, 8, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]);
}

@safe unittest // putMpint(magnitude bytes) == putMpint(BigInt(false, magnitude)), no round-trip
{
    void same(ubyte[] magnitude)
    {
        SshBuffer a;
        a.putMpint(cast(const(ubyte)[]) magnitude);
        SshBuffer b;
        b.putMpint(BigInt(false, magnitude));
        assert(a.data == b.data);
    }

    same([]);                                  // empty -> zero
    same([0x00]);                              // leading zeros stripped -> zero
    same([0x00, 0x00, 0x09, 0xa3]);            // leading zeros stripped
    same([0x80]);                              // high bit -> 0x00 padded
    same([0x09, 0xa3, 0x78, 0xf9]);            // no padding
    same([0xff, 0xff]);                        // high bit on multi-byte
    ubyte[32] k; foreach (i; 0 .. 32) k[i] = cast(ubyte)(0x70 + i);
    same(k[]);

    // explicit vectors
    SshBuffer z; z.putMpint(cast(const(ubyte)[]) []); assert(z.data == [0, 0, 0, 0]);
    SshBuffer p; p.putMpint(cast(const(ubyte)[]) [0x80]); assert(p.data == [0, 0, 0, 2, 0x00, 0x80]);
}

@safe unittest
{
    SshBuffer w;
    ubyte[] blob = [0xaa, 0xbb, 0xcc];
    w.putRaw(blob);
    assert(w.data == blob); // no length prefix

    auto r = SshBuffer(blob);
    assert(r.readRaw(3) == blob);
    assert(r.pos == 3);
}

@safe unittest
{
    SshBuffer w;
    w.putStr("hello");
    assert(SshBuffer(w.data).readStr() == "hello");
}

/// Secret buffers with deterministic zeroization.
///
/// Best-effort: zeroizes on free and keeps long-lived keys off the GC heap. Does NOT
/// defend against swap, live-memory reads (ptrace, /proc/PID/mem), side channels, or
/// copies that crypto/derivation leave in other (GC) buffers. mlock is intentionally
/// not used.
module dssh.secret;

import core.stdc.stdlib : malloc, free;

// Declared locally with @nogc nothrow; the deimos prototype lacks both.
pragma(mangle, "OPENSSL_cleanse")
extern(C) void opensslCleanse(void* ptr, size_t len) @nogc nothrow @system;

/// Zero memory so the optimizer cannot elide it. A plain memset/loop is dropped at -O3
/// once the buffer is dead (verified); OPENSSL_cleanse is an opaque call that survives.
void secureZero(ubyte* p, size_t n) @system @nogc nothrow
{
    opensslCleanse(p, n);
}

/// Slice overload: @safe because the slice carries its own valid pointer and length.
void secureZero(ubyte[] buf) @trusted @nogc nothrow
{
    if (buf.length)
        secureZero(buf.ptr, buf.length);
}

/// Non-copyable secret buffer. malloc-backed, zeroized on destruction.
struct SecretBuf
{
    private ubyte* p;
    private size_t len;
    private size_t cap;

    @disable this(this);

    this(size_t n) @trusted @nogc nothrow
    {
        p = cast(ubyte*) malloc(n);
        if (p !is null)
        {
            cap = n;
            len = n;
            secureZero(p, cap);
        }
    }

    ~this() @trusted @nogc nothrow
    {
        if (p !is null) // also covers the moved-from (T.init) case
        {
            secureZero(p, cap);
            free(p);
            p = null;
        }
    }

    // inout collapses the mutable/const accessors; immutable SecretBuf is unconstructible
    // (the zeroizing destructor mutates), so that instantiation is never reached.
    inout(ubyte)[] opSlice() inout @trusted @nogc nothrow return { return p[0 .. len]; }

    size_t length() const @safe @nogc nothrow { return len; }
}

@safe unittest // secureZero(slice) wipes the buffer and is @safe-callable
{
    ubyte[] b = [1, 2, 3, 4, 5];
    secureZero(b);
    assert(b == [0, 0, 0, 0, 0]);

    ubyte[] empty;
    secureZero(empty); // no crash on empty
}

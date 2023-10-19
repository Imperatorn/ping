module utils;

T toType(T)(ubyte[] buf)
{
    T result = 0;

    foreach (b; buf[0 .. T.sizeof])
        result = cast(T)(result << 8) | b;

    return result;
}

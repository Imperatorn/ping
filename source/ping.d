module ping;

import std.socket;
import std.format;
import std.stdio;
import std.datetime.stopwatch;
import core.time;
import std.datetime;
import core.stdc.time;
import std.array;
import std.conv;

version (Linux)
{
    import core.sys.linux.sys.socket;
}
import core.thread.osthread;

import ipcmp;
import utils;

const int PING_PKT_S = 64; // Ping packet size

struct PingPacket
{
    icmp_hdr hdr;
    ubyte[PING_PKT_S - icmp_hdr.sizeof] msg;
}

struct PingReply
{
    ubyte type; // ICMP message type (should be 0x00 for Echo Reply)
    ubyte code; // ICMP message code (should be 0x00 for Echo Reply)
    ushort checksum; // ICMP header checksum
    ushort identifier; // Identifier field (16 bits)
    ushort sequence; // Sequence number field (16 bits)
    int timestamp; // Use this field to store the timestamp
}

ushort checksum(void* data, size_t len)
{
    ushort* buf = cast(ushort*) data;
    uint sum = 0;

    while (len > 1)
    {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1)
    {
        sum += *cast(ubyte*) buf;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return cast(ushort)(~sum);
}

PingReply sendPing(int sockfd, sockaddr_in* dest_addr, string host)
{
    int ttl = 64;
    int seq = 0;

    PingPacket packet = PingPacket();
    packet.hdr.type = 8; // ICMP Echo Request
    packet.hdr.code = 0;
    packet.hdr.un.echo.id = cast(ushort)(getpid() & 0xFFFF);

    packet.hdr.un.echo.sequence = cast(ushort)(seq++);

    packet.hdr.checksum = checksum(&packet, PingPacket.sizeof);

    StopWatch sw = StopWatch(AutoStart.yes);

    int sentBytes = cast(int) sendto(sockfd, &packet, PingPacket.sizeof, 0, cast(sockaddr*) dest_addr, sockaddr_in
            .sizeof);

    if (sentBytes == -1)
        stderr.writeln("Error sending packet");

    ubyte[PING_PKT_S] recvBuf;
    sockaddr_in replyAddr;
    int addrLen = sockaddr_in.sizeof;

    version (Windows)
        recvfrom(sockfd, recvBuf.ptr, recvBuf.length, 0, cast(sockaddr*)&replyAddr, &addrLen);
    else
        recvfrom(sockfd, recvBuf.ptr, recvBuf.length, 0, cast(sockaddr*)&replyAddr, cast(uint*)&addrLen);

    long time = sw.peek.total!"msecs";

    PingReply reply;

    // Parse the fields from recvBuf
    reply.type = recvBuf[0];
    reply.code = recvBuf[1];
    reply.checksum = recvBuf[2 .. 4].toType!ushort;
    reply.identifier = recvBuf[4 .. 6].toType!ushort;
    reply.sequence = recvBuf[6 .. 8].toType!ushort;
    reply.timestamp = recvBuf[8 .. 12].toType!int;

    writeln(format("Reply from %s: seq=%d ttl=%d time=%.2f ms", host, seq, ttl, time));

    return reply;
}

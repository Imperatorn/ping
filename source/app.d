module app;
import std.stdio;
import std.string;
import std.socket;
import core.thread;
import std.datetime.stopwatch;
import ipcmp;
import utils;

const int PING_PKT_S = 64;

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

void main(string[] args)
{
    if (args.length < 2)
    {
        writeln("Supply a hostname as parameter");
        return;
    }

    string host = args[1];

    int seq = 0;

    PingPacket packet = PingPacket();
    packet.hdr.type = 8;
    packet.hdr.code = 0;
    packet.hdr.un.echo.id = cast(ushort)(getpid() & 0xFFFF);

    packet.hdr.un.echo.sequence = cast(ushort)(seq++);

    packet.hdr.checksum = checksum(&packet, PingPacket.sizeof);

    Address[] addresses = getAddress(host);

    Socket s = new Socket(AddressFamily.INET, SocketType.RAW, ProtocolType.ICMP);

    StopWatch sw = StopWatch(AutoStart.yes);
    s.sendTo((cast(ubyte*)&packet)[0 .. packet.sizeof], addresses[0]);

    ubyte[64] recvBuf;
    s.receiveFrom(recvBuf);

    long time = sw.peek.total!"msecs";

    // PingReply reply;

    // // Parse the fields from recvBuf
    // reply.type = recvBuf[0];
    // reply.code = recvBuf[1];
    // reply.checksum = recvBuf[2 .. 4].toType!ushort;
    // reply.identifier = recvBuf[4 .. 6].toType!ushort;
    // reply.sequence = recvBuf[6 .. 8].toType!ushort;
    // reply.timestamp = recvBuf[8 .. 12].toType!int;

    writeln(format("Reply from %s: time=%.2f ms", host, time));
}
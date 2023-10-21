module app;

version(Windows)
import core.sys.windows.winsock2;
else
{
import core.sys.linux.sys.socket;
import core.sys.posix.netinet.in_;
import core.sys.posix.netdb;
}

import std.stdio;
import std.string;

import ipcmp;
import ping;

void main(string[] args)
{
    if (args.length < 2)
    {
        writeln("Supply a hostname as parameter");
        return;
    }

    auto hostname = args[1].toStringz;

    hostent hostEntity = *gethostbyname(hostname);

    sockaddr_in destAddr;
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = 0;
    destAddr.sin_addr = cast(in_addr)((cast(in_addr*) hostEntity.h_addr_list[0])[0]);

    int sockfd = cast(int) socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sockfd == -1)
    {
        writeln("Failed to create socket");
        return;
    }

    sendPing(sockfd, &destAddr, hostname.fromStringz);
}


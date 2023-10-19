module ipcmp;

@nogc nothrow:
extern(C): __gshared:
/* Copyright (C) 1991, 92, 93, 95, 96, 97, 99 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

enum __NETINET_IP_ICMP_H =    1;

public import core.sys.posix.sys.types;

struct icmp_hdr
{
  uint type = void;                /* message type */
  uint code = void;                /* type sub-code */
  ushort checksum = void;
  union _Un {
    struct _Echo {
      ushort id = void;
      ushort sequence = void;
    }_Echo echo = void;                        /* echo datagram */
    uint gateway = void;        /* gateway address */
    struct _Frag {
      ushort __unused = void;
      ushort mtu = void;
    }_Frag frag = void;                        /* path mtu discovery */
  }_Un un = void;
}

enum ICMP_ECHOREPLY =                0        /* Echo Reply                        */;
enum ICMP_DEST_UNREACH =        3        /* Destination Unreachable        */;
enum ICMP_SOURCE_QUENCH =        4        /* Source Quench                */;
enum ICMP_REDIRECT =                5        /* Redirect (change route)        */;
enum ICMP_ECHO =                8        /* Echo Request                        */;
enum ICMP_TIME_EXCEEDED =        11        /* Time Exceeded                */;
enum ICMP_PARAMETERPROB =        12        /* Parameter Problem                */;
enum ICMP_TIMESTAMP =                13        /* Timestamp Request                */;
enum ICMP_TIMESTAMPREPLY =        14        /* Timestamp Reply                */;
enum ICMP_INFO_REQUEST =        15        /* Information Request                */;
enum ICMP_INFO_REPLY =                16        /* Information Reply                */;
enum ICMP_ADDRESS =                17        /* Address Mask Request                */;
enum ICMP_ADDRESSREPLY =        18        /* Address Mask Reply                */;
enum NR_ICMP_TYPES =                18;


/* Codes for UNREACH. */
enum ICMP_NET_UNREACH =        0        /* Network Unreachable                */;
enum ICMP_HOST_UNREACH =        1        /* Host Unreachable                */;
enum ICMP_PROT_UNREACH =        2        /* Protocol Unreachable                */;
enum ICMP_PORT_UNREACH =        3        /* Port Unreachable                */;
enum ICMP_FRAG_NEEDED =        4        /* Fragmentation Needed/DF set        */;
enum ICMP_SR_FAILED =                5        /* Source Route failed                */;
enum ICMP_NET_UNKNOWN =        6;
enum ICMP_HOST_UNKNOWN =        7;
enum ICMP_HOST_ISOLATED =        8;
enum ICMP_NET_ANO =                9;
enum ICMP_HOST_ANO =                10;
enum ICMP_NET_UNR_TOS =        11;
enum ICMP_HOST_UNR_TOS =        12;
enum ICMP_PKT_FILTERED =        13        /* Packet filtered */;
enum ICMP_PREC_VIOLATION =        14        /* Precedence violation */;
enum ICMP_PREC_CUTOFF =        15        /* Precedence cut off */;
enum NR_ICMP_UNREACH =                15        /* instead of hardcoding immediate value */;

/* Codes for REDIRECT. */
enum ICMP_REDIR_NET =                0        /* Redirect Net                        */;
enum ICMP_REDIR_HOST =                1        /* Redirect Host                */;
enum ICMP_REDIR_NETTOS =        2        /* Redirect Net for TOS                */;
enum ICMP_REDIR_HOSTTOS =        3        /* Redirect Host for TOS        */;

/* Codes for TIME_EXCEEDED. */
enum ICMP_EXC_TTL =                0        /* TTL count exceeded                */;
enum ICMP_EXC_FRAGTIME =        1        /* Fragment Reass time exceeded        */;


version (__USE_BSD) {
/*
 * Copyright (c) 1982, 1986, 1993
 *        The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *        @(#)ip_icmp.h        8.1 (Berkeley) 6/10/93
 */

public import core.sys.posix.netinet;
public import core.sys.posix.netinet.in_;
public import core.sys.posix.netinet.tcp;

/*
 * Internal of an ICMP Router Advertisement
 */
struct icmp_ra_addr
{
  uint ira_addr;
  uint ira_preference;
}

struct icmp
{
  uint icmp_type;        /* type of message, see below */
  uint icmp_code;        /* type sub code */
  ushort icmp_cksum;        /* ones complement checksum of struct */
  union _Icmp_hun {
    u_char ih_pptr;                /* ICMP_PARAMPROB */
    in_addr ih_gwaddr;        /* gateway address */
    struct ih_idseq {
      ushort icd_id;
      ushort icd_seq;
    }ih_idseq ih_idseq;
    uint ih_void;

    /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
    struct ih_pmtu {
      ushort ipm_void;
      ushort ipm_nextmtu;
    }ih_pmtu ih_pmtu;

    struct ih_rtradv {
      uint irt_num_addrs;
      uint irt_wpa;
      ushort irt_lifetime;
    }ih_rtradv ih_rtradv;
  }_Icmp_hun icmp_hun;
enum        icmp_pptr =        icmp_hun.ih_pptr;
enum        icmp_gwaddr =        icmp_hun.ih_gwaddr;
enum        icmp_id =                icmp_hun.ih_idseq.icd_id;
enum        icmp_seq =        icmp_hun.ih_idseq.icd_seq;
enum        icmp_void =        icmp_hun.ih_void;
enum        icmp_pmvoid =        icmp_hun.ih_pmtu.ipm_void;
enum        icmp_nextmtu =        icmp_hun.ih_pmtu.ipm_nextmtu;
enum        icmp_num_addrs =        icmp_hun.ih_rtradv.irt_num_addrs;
enum        icmp_wpa =        icmp_hun.ih_rtradv.irt_wpa;
enum        icmp_lifetime =        icmp_hun.ih_rtradv.irt_lifetime;
  union _Icmp_dun {
    struct _Id_ts {
      uint its_otime;
      uint its_rtime;
      uint its_ttime;
    }_Id_ts id_ts;
    struct _Id_ip {
      ip idi_ip;
      /* options and then 64 bits of data */
    }_Id_ip id_ip;
    icmp_ra_addr id_radv;
    uint id_mask;
    uint[1] id_data;
  }_Icmp_dun icmp_dun;
enum        icmp_otime =        icmp_dun.id_ts.its_otime;
enum        icmp_rtime =        icmp_dun.id_ts.its_rtime;
enum        icmp_ttime =        icmp_dun.id_ts.its_ttime;
enum        icmp_ip =                icmp_dun.id_ip.idi_ip;
enum        icmp_radv =        icmp_dun.id_radv;
enum        icmp_mask =        icmp_dun.id_mask;
enum        icmp_data =        icmp_dun.id_data;
}

/*
 * Lower bounds on packet lengths for various types.
 * For the error advice packets must first insure that the
 * packet is large enough to contain the returned ip header.
 * Only then can we do the check to see if 64 bits of packet
 * data have been returned, since we need to check the returned
 * ip header length.
 */
enum        ICMP_MINLEN =        8                                /* abs minimum */;
enum        ICMP_TSLEN =        (8 + 3 * sizeof(n_time))        /* timestamp */;
enum        ICMP_MASKLEN =        12                                /* address mask */;
enum        ICMP_ADVLENMIN =        (8 + sizeof(ip) + 8)        /* min */;
version (_IP_VHL) {} else {
enum string        ICMP_ADVLEN(string p) = `(8 + ((` ~ p ~ `).icmp_ip.ip_hl << 2) + 8)`;
        /* N.B.: must separately check that ip_hl >= 5 */
} version (_IP_VHL) {
enum string        ICMP_ADVLEN(string p) = `(8 + (IP_VHL_HL((` ~ p ~ `).icmp_ip.ip_vhl) << 2) + 8)`;
        /* N.B.: must separately check that header length >= 5 */
}

/* Definition of type and code fields. */
/* defined above: ICMP_ECHOREPLY, ICMP_REDIRECT, ICMP_ECHO */
enum        ICMP_UNREACH =                3                /* dest unreachable, codes: */;
enum        ICMP_SOURCEQUENCH =        4                /* packet lost, slow down */;
enum        ICMP_ROUTERADVERT =        9                /* router advertisement */;
enum        ICMP_ROUTERSOLICIT =        10                /* router solicitation */;
enum        ICMP_TIMXCEED =                11                /* time exceeded, code: */;
enum        ICMP_PARAMPROB =                12                /* ip header bad */;
enum        ICMP_TSTAMP =                13                /* timestamp request */;
enum        ICMP_TSTAMPREPLY =        14                /* timestamp reply */;
enum        ICMP_IREQ =                15                /* information request */;
enum        ICMP_IREQREPLY =                16                /* information reply */;
enum        ICMP_MASKREQ =                17                /* address mask request */;
enum        ICMP_MASKREPLY =                18                /* address mask reply */;

enum        ICMP_MAXTYPE =                18;

/* UNREACH codes */
enum        ICMP_UNREACH_NET =                0        /* bad net */;
enum        ICMP_UNREACH_HOST =                1        /* bad host */;
enum        ICMP_UNREACH_PROTOCOL =                2        /* bad protocol */;
enum        ICMP_UNREACH_PORT =                3        /* bad port */;
enum        ICMP_UNREACH_NEEDFRAG =                4        /* IP_DF caused drop */;
enum        ICMP_UNREACH_SRCFAIL =                5        /* src route failed */;
enum        ICMP_UNREACH_NET_UNKNOWN =        6        /* unknown net */;
enum        ICMP_UNREACH_HOST_UNKNOWN =       7        /* unknown host */;
enum        ICMP_UNREACH_ISOLATED =                8        /* src host isolated */;
enum        ICMP_UNREACH_NET_PROHIB =                9        /* net denied */;
enum        ICMP_UNREACH_HOST_PROHIB =        10        /* host denied */;
enum        ICMP_UNREACH_TOSNET =                11        /* bad tos for net */;
enum        ICMP_UNREACH_TOSHOST =                12        /* bad tos for host */;
enum        ICMP_UNREACH_FILTER_PROHIB =      13        /* admin prohib */;
enum        ICMP_UNREACH_HOST_PRECEDENCE =    14        /* host prec vio. */;
enum        ICMP_UNREACH_PRECEDENCE_CUTOFF =  15        /* prec cutoff */;

/* REDIRECT codes */
enum        ICMP_REDIRECT_NET =        0                /* for network */;
enum        ICMP_REDIRECT_HOST =        1                /* for host */;
enum        ICMP_REDIRECT_TOSNET =        2                /* for tos and net */;
enum        ICMP_REDIRECT_TOSHOST =        3                /* for tos and host */;

/* TIMEXCEED codes */
enum        ICMP_TIMXCEED_INTRANS =        0                /* ttl==0 in transit */;
enum        ICMP_TIMXCEED_REASS =        1                /* ttl==0 in reass */;

/* PARAMPROB code */
enum        ICMP_PARAMPROB_OPTABSENT = 1                /* req. opt. absent */;

enum string        ICMP_INFOTYPE(string type) = `
        ((` ~ type ~ `) == ICMP_ECHOREPLY || (` ~ type ~ `) == ICMP_ECHO || 
        (` ~ type ~ `) == ICMP_ROUTERADVERT || (` ~ type ~ `) == ICMP_ROUTERSOLICIT || 
        (` ~ type ~ `) == ICMP_TSTAMP || (` ~ type ~ `) == ICMP_TSTAMPREPLY || 
        (` ~ type ~ `) == ICMP_IREQ || (` ~ type ~ `) == ICMP_IREQREPLY || 
        (` ~ type ~ `) == ICMP_MASKREQ || (` ~ type ~ `) == ICMP_MASKREPLY)`;

} /* __USE_BSD */
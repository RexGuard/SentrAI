/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* SentrAI Gate: types shared by the kernel programs and the control tool.
 *
 * The control tool mirrors these structs in Go (internal/kern/types.go).
 * Keep both sides in step: same field order, same sizes.
 */
#pragma once

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u16 __le16;
typedef __u32 __le32;
typedef __u32 __wsum;

/* Just enough of the kernel's own definitions, so the build needs no
 * kernel headers on the machine. */
enum {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_RINGBUF = 27,
};
enum { BPF_ANY = 0, BPF_NOEXIST = 1, BPF_EXIST = 2 };
enum { BPF_F_NO_PREALLOC = 1 };
enum { XDP_ABORTED = 0, XDP_DROP = 1, XDP_PASS = 2 };
#define TCX_NEXT (-1)

struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

/* Leading part of the kernel's struct __sk_buff, up to data_end. */
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
};

#include "headers/bpf_helpers.h"
#include "headers/bpf_endian.h"

/* ---- packet headers ---- */

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMPV6 58

struct ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__be16 h_proto;
} __attribute__((packed));

struct vlanhdr {
	__be16 tci;
	__be16 proto;
};

struct iphdr {
	__u8 vihl; /* version (high 4 bits), header length in words (low 4) */
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 check;
	__be32 saddr;
	__be32 daddr;
};

struct ipv6hdr {
	__u8 vprio;
	__u8 flow[3];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u8 saddr[16];
	__u8 daddr[16];
};

struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u8 doff; /* data offset in words (high 4 bits) */
	__u8 flags;
	__be16 window;
	__u16 check;
	__be16 urg;
};

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__u16 check;
};

/* ---- shared with the control tool ---- */

/* Every address is kept as 16 bytes. IPv4 is stored as ::ffff:a.b.c.d. */
struct addr_key {
	__u8 a[16];
};

struct lpm_key {
	__u32 prefixlen;
	__u8 a[16];
};

struct flow_key {
	__u8 a[16];    /* the far end */
	__be16 rport;  /* far end port */
	__be16 lport;  /* our port */
	__u8 proto;
	__u8 pad[3];
};

/* Settings switches (gate_cfg.flags). */
#define F_ENABLED (1u << 0)
#define F_OBSERVE (1u << 1)        /* count what would be dropped, drop nothing */
#define F_DROP_BOGON (1u << 2)
#define F_DROP_PRIVATE (1u << 3)
#define F_DROP_BAD_TCP (1u << 4)
#define F_DROP_FRAGS (1u << 5)
#define F_DROP_FRAGS_ATTACK (1u << 6)
#define F_AMP (1u << 7)            /* reflection / amplification filter */
#define F_REFLECT (1u << 8)        /* unasked-for SYN-ACK filter (needs F_TRACK) */
#define F_RATE (1u << 9)           /* per-address scoring and bans */
#define F_TOKEN (1u << 10)         /* per-address token bucket */
#define F_NEWSRC (1u << 11)        /* new-address limit while under attack */
#define F_PANIC (1u << 12)         /* per-CPU overload breaker */
#define F_ATTACK (1u << 13)        /* set by the control tool: under attack */
#define F_TRACK (1u << 14)         /* set by the control tool: outgoing flows are tracked */
#define F_HAS_ALLOW (1u << 15)
#define F_HAS_SUBNETS (1u << 16)

#define AMP_SLOTS 8
#define STRIKE_SLOTS 8

struct gate_cfg {
	__u64 bps;              /* bytes per second, per address */
	__u32 flags;
	__u32 pps;
	__u32 tcp_pps;
	__u32 udp_pps;
	__u32 icmp_pps;
	__u32 syn_pps;
	__u32 s_pps;            /* points added when a limit is passed */
	__u32 s_bps;
	__u32 s_tcp;
	__u32 s_udp;
	__u32 s_icmp;
	__u32 s_syn;
	__u32 score_ban;        /* points at which an address is banned */
	__u32 score_decay;      /* points taken off after each clean second */
	__u32 ban_secs;
	__u32 strike_mult[STRIKE_SLOTS];
	__u32 attack_pct;       /* limits shrink to this percent under attack */
	__u32 attack_ip_pps;    /* hard per-address cap under attack, 0 = off */
	__u32 token_rate;
	__u32 token_burst;
	__u32 newsrc_limit;     /* new addresses per second per CPU under attack */
	__u32 panic_pps;        /* per CPU */
	__u32 panic_drop_pct;
	__u32 pad;
	__u16 amp_port[AMP_SLOTS];
	__u16 amp_min[AMP_SLOTS];
};

struct ip_state {
	__u64 win_start;
	__u64 bytes;
	__u64 tokens_ts;
	__u32 pkts;
	__u32 tcp;
	__u32 udp;
	__u32 icmp;
	__u32 syn;
	__u32 score;
	__u32 strikes;
	__u32 tokens;
	__u32 flagged;          /* 2 bits per limit: how far past it this second */
	__u32 pad;
};

/* Which limit, as a shift into ip_state.flagged / ban_val.reason. */
#define M_PPS 0
#define M_BPS 2
#define M_TCP 4
#define M_UDP 6
#define M_ICMP 8
#define M_SYN 10
#define R_MANUAL (1u << 16)
#define R_SUBNET (1u << 17)

struct ban_val {
	__u64 until;            /* kernel clock, ns. 0 = until removed */
	__u32 reason;
	__u32 strikes;
};

struct ctr {
	__u64 pkts;
	__u64 bytes;
};

/* Counter slots. One per way a packet can leave the pipeline, plus tallies. */
enum {
	C_SEEN = 0,
	C_PASS,
	C_PASS_NONIP,
	C_PASS_ALLOW,
	C_PASS_LOCAL,
	C_DROP_BANNED,
	C_DROP_SUBNET,
	C_DROP_PANIC,
	C_DROP_MALFORMED,
	C_DROP_BOGON,
	C_DROP_PRIVATE,
	C_DROP_TCPFLAGS,
	C_DROP_FRAG,
	C_DROP_AMP,
	C_DROP_REFLECT,
	C_DROP_NEWSRC,
	C_DROP_TOKEN,
	C_DROP_CAP,
	C_DROP_RATE,
	C_WOULD_DROP,
	C_TCP,
	C_UDP,
	C_ICMP,
	C_SYN,
	C_OTHER,
	C_NEW_SRC,
	C_NEW_BAN,
	C_MAX = 32,
};

struct event {
	__u64 ts;
	__u64 bytes;
	__u8 a[16];
	__u32 reason;
	__u32 score;
	__u32 strikes;
	__u32 ban_secs;
	__u32 pkts;
	__u32 tcp;
	__u32 udp;
	__u32 icmp;
	__u32 syn;
	__u32 pad;
};

struct cpu_win {
	__u64 panic_win;
	__u64 newsrc_win;
	__u32 panic_pkts;
	__u32 newsrc;
};

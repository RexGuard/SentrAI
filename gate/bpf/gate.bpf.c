// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* SentrAI Gate: the packet filter that runs inside the kernel.
 *
 * gate_ingress (XDP) looks at every packet as it comes off the network card
 * and decides pass or drop, in fixed stages:
 *
 *   1 read       work out who sent it and what it is
 *   2 allow      addresses on the allow list skip everything else
 *   3 banned     drop addresses and networks that are banned
 *   4 breaker    under extreme load, shed a share of traffic to stay alive
 *   5 checks     drop packets that cannot be real (broken, impossible sender)
 *   6 reflection drop replies nobody on this machine asked for
 *   7 rate       score each address against its limits, ban at the line
 *
 * gate_egress (TC) only takes notes: it records the connections this machine
 * starts, so stage 6 and 7 can tell an answer from an attack.
 *
 * The gate only ever drops or passes packets arriving here. It never sends
 * anything back at the sender.
 */
#include "gate.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Set by the control tool before loading. The kernel removes the code a
 * switched-off stage would use, so an older kernel never has to accept it. */
volatile const __u32 gate_level = 2;  /* 0 core, 1 + rate, 2 everything */
volatile const __u32 gate_events = 1; /* 0 when the kernel has no ring buffer */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct gate_cfg);
} cfg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, C_MAX);
	__type(key, __u32);
	__type(value, struct ctr);
} counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cpu_win);
} cpu_wins SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, __u32);
} allow SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000000);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct addr_key);
	__type(value, struct ban_val);
} bans SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, struct ban_val);
} subnets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 262144);
	__type(key, struct addr_key);
	__type(value, struct ip_state);
} ip_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 262144);
	__type(key, struct flow_key);
	__type(value, __u64);
} flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} events SEC(".maps");

#define NSEC 1000000000ULL
#define FLOW_FRESH (30 * NSEC)

/* What stage 1 learns about a packet. */
struct pkt {
	struct addr_key src;
	struct addr_key dst;
	__u64 now;
	__u32 len;
	__u32 v4src;     /* host order, IPv4 only */
	__be16 sport;
	__be16 dport;
	__u16 payload;   /* UDP payload bytes */
	__u8 proto;
	__u8 tcp_flags;
	__u8 v6;
	__u8 frag;       /* any fragment */
	__u8 has_l4;
	__u8 dns_reply;
};

enum { P_OK = 0, P_NONIP = 1, P_BAD = 2 };

static __always_inline void count(__u32 slot, __u64 bytes)
{
	struct ctr *c = bpf_map_lookup_elem(&counters, &slot);
	if (c) {
		c->pkts++;
		c->bytes += bytes;
	}
}

static __always_inline void map_v4(struct addr_key *k, __be32 addr)
{
	__builtin_memset(k->a, 0, 10);
	k->a[10] = 0xff;
	k->a[11] = 0xff;
	__builtin_memcpy(&k->a[12], &addr, 4);
}

/* Reads TCP / UDP details at l4. Returns P_OK or P_BAD. */
static __always_inline int read_l4(void *l4, void *end, struct pkt *p)
{
	if (p->proto == IPPROTO_TCP) {
		struct tcphdr *t = l4;
		if ((void *)(t + 1) > end)
			return P_BAD;
		if ((t->doff >> 4) < 5)
			return P_BAD;
		p->sport = t->source;
		p->dport = t->dest;
		p->tcp_flags = t->flags & 0x3f;
		p->has_l4 = 1;
	} else if (p->proto == IPPROTO_UDP) {
		struct udphdr *u = l4;
		__u16 ulen;
		if ((void *)(u + 1) > end)
			return P_BAD;
		ulen = bpf_ntohs(u->len);
		if (ulen < sizeof(*u))
			return P_BAD;
		p->sport = u->source;
		p->dport = u->dest;
		p->payload = ulen - sizeof(*u);
		p->has_l4 = 1;
		if (gate_level >= 2) {
			/* DNS: the top bit of the third byte says "this is an answer". */
			__u8 *d = (void *)(u + 1);
			if ((void *)(d + 3) <= end && (d[2] & 0x80))
				p->dns_reply = 1;
		}
	}
	return P_OK;
}

/* Stage 1. Works for both hooks: give it the packet bounds. */
static __always_inline int read_packet(void *data, void *end, struct pkt *p, int walk_ext)
{
	struct ethhdr *eth = data;
	__u32 off = sizeof(*eth);
	__be16 proto;
	int i;

	if ((void *)(eth + 1) > end)
		return P_NONIP;
	proto = eth->h_proto;

	for (i = 0; i < 2; i++) {
		struct vlanhdr *v;
		if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
			break;
		v = data + off;
		if ((void *)(v + 1) > end)
			return P_NONIP;
		proto = v->proto;
		off += sizeof(*v);
	}

	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = data + off;
		__u32 ihl;
		if ((void *)(ip + 1) > end)
			return P_BAD;
		ihl = (ip->vihl & 0x0f) * 4;
		if ((ip->vihl >> 4) != 4 || ihl < sizeof(*ip))
			return P_BAD;
		if (bpf_ntohs(ip->tot_len) < ihl)
			return P_BAD;
		map_v4(&p->src, ip->saddr);
		map_v4(&p->dst, ip->daddr);
		p->v4src = bpf_ntohl(ip->saddr);
		p->proto = ip->protocol;
		if (ip->frag_off & bpf_htons(0x3fff)) {
			p->frag = 1;
			if (ip->frag_off & bpf_htons(0x1fff))
				return P_OK; /* a later piece: no TCP/UDP header in it */
		}
		return read_l4(data + off + ihl, end, p);
	}

	if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = data + off;
		__u8 next;
		if ((void *)(ip6 + 1) > end)
			return P_BAD;
		if ((ip6->vprio >> 4) != 6)
			return P_BAD;
		__builtin_memcpy(p->src.a, ip6->saddr, 16);
		__builtin_memcpy(p->dst.a, ip6->daddr, 16);
		p->v6 = 1;
		next = ip6->nexthdr;
		off += sizeof(*ip6);
		if (walk_ext) {
			for (i = 0; i < 4; i++) {
				__u8 *h;
				if (next != 0 && next != 43 && next != 60 && next != 44)
					break;
				if (off > 1024)
					return P_BAD;
				h = data + off;
				if ((void *)(h + 8) > end)
					return P_BAD;
				if (next == 44) {
					p->frag = 1;
					next = h[0];
					off += 8;
					if (h[2] || (h[3] & 0xf8)) {
						p->proto = next;
						return P_OK;
					}
				} else {
					next = h[0];
					off += ((__u32)h[1] + 1) * 8;
				}
			}
		}
		p->proto = next;
		if (off > 1024)
			return P_BAD;
		return read_l4(data + off, end, p);
	}

	return P_NONIP;
}

static __always_inline int verdict_drop(struct gate_cfg *cfg, __u32 slot, __u32 len)
{
	count(slot, len);
	if (cfg->flags & F_OBSERVE) {
		count(C_WOULD_DROP, len);
		return XDP_PASS;
	}
	return XDP_DROP;
}

/* Senders that can never be real on the open internet. */
static __always_inline int v4_bogon(struct pkt *p)
{
	__u32 s = p->v4src;
	__u32 top = s >> 24;

	if (top == 0) /* 0.0.0.0/8, except a machine asking for an address (DHCP) */
		return !(p->proto == IPPROTO_UDP && p->dport == bpf_htons(67));
	if (top == 127 || top >= 224)
		return 1;
	if ((s >> 8) == 0xC00002 || (s >> 8) == 0xC63364 || (s >> 8) == 0xCB0071)
		return 1; /* documentation ranges */
	return 0;
}

/* Private and provider-internal ranges. Often real on cloud machines
 * (metadata service, load balancer probes), so this check is off by default. */
static __always_inline int v4_private(__u32 s)
{
	return (s >> 24) == 10 || (s >> 20) == 0xAC1 || (s >> 16) == 0xC0A8 ||
	       (s >> 22) == 0x191 || (s >> 16) == 0xA9FE || (s >> 17) == 0x6309;
}

static __always_inline int bad_tcp_flags(__u8 f)
{
	if (f == 0)
		return 1;
	if ((f & (TCP_SYN | TCP_FIN)) == (TCP_SYN | TCP_FIN))
		return 1;
	if ((f & (TCP_SYN | TCP_RST)) == (TCP_SYN | TCP_RST))
		return 1;
	if ((f & (TCP_FIN | TCP_RST)) == (TCP_FIN | TCP_RST))
		return 1;
	if ((f & TCP_FIN) && !(f & TCP_ACK))
		return 1;
	return 0;
}

static __always_inline void flow_key_of(struct flow_key *k, struct addr_key *far,
					__be16 rport, __be16 lport, __u8 proto)
{
	__builtin_memset(k, 0, sizeof(*k));
	__builtin_memcpy(k->a, far->a, 16);
	k->rport = rport;
	k->lport = lport;
	k->proto = proto;
}

/* Did this machine start (or recently talk on) this exact conversation? */
static __always_inline int asked_for(struct pkt *p, __u64 max_age)
{
	struct flow_key k;
	__u64 *ts;

	flow_key_of(&k, &p->src, p->sport, p->dport, p->proto);
	ts = bpf_map_lookup_elem(&flows, &k);
	if (!ts)
		return 0;
	if (max_age && p->now - *ts > max_age)
		return 0;
	return 1;
}

static __always_inline __u64 scaled(__u64 limit, __u32 pct)
{
	return limit * pct / 100;
}

/* Adds points the first time a limit is passed in a second, and more if the
 * address goes on to pass it two or four times over. */
static __always_inline void check_limit(struct ip_state *st, __u32 shift, __u64 seen,
					__u64 limit, __u32 points)
{
	__u32 level, mult, old, old_mult;

	if (!limit || seen <= limit)
		return;
	if (seen > limit * 4) {
		level = 3;
		mult = 4;
	} else if (seen > limit * 2) {
		level = 2;
		mult = 2;
	} else {
		level = 1;
		mult = 1;
	}
	old = (st->flagged >> shift) & 3;
	if (level <= old)
		return;
	old_mult = old == 3 ? 4 : old;
	st->score += points * (mult - old_mult);
	st->flagged = (st->flagged & ~(3u << shift)) | (level << shift);
}

static __always_inline void check_limits(struct gate_cfg *cfg, struct ip_state *st, int exempt)
{
	__u32 pct = 100;

	if ((cfg->flags & F_ATTACK) && cfg->attack_pct && cfg->attack_pct < 100)
		pct = cfg->attack_pct;
	if (!exempt) {
		check_limit(st, M_PPS, st->pkts, scaled(cfg->pps, pct), cfg->s_pps);
		check_limit(st, M_BPS, st->bytes, scaled(cfg->bps, pct), cfg->s_bps);
		check_limit(st, M_TCP, st->tcp, scaled(cfg->tcp_pps, pct), cfg->s_tcp);
	}
	check_limit(st, M_UDP, st->udp, scaled(cfg->udp_pps, pct), cfg->s_udp);
	check_limit(st, M_ICMP, st->icmp, scaled(cfg->icmp_pps, pct), cfg->s_icmp);
	check_limit(st, M_SYN, st->syn, scaled(cfg->syn_pps, pct), cfg->s_syn);
}

static __always_inline void ban_now(struct gate_cfg *cfg, struct pkt *p, struct ip_state *st)
{
	struct ban_val b = {};
	__u32 slot = st->strikes;
	__u64 secs;

	if (slot >= STRIKE_SLOTS)
		slot = STRIKE_SLOTS - 1;
	secs = (__u64)cfg->ban_secs * cfg->strike_mult[slot & (STRIKE_SLOTS - 1)];
	if (secs == 0)
		secs = cfg->ban_secs ? cfg->ban_secs : 60;
	if (secs > 30 * 86400)
		secs = 30 * 86400;

	b.until = p->now + secs * NSEC;
	b.reason = st->flagged;
	b.strikes = st->strikes + 1;
	bpf_map_update_elem(&bans, &p->src, &b, BPF_ANY);
	count(C_NEW_BAN, 0);

	if (gate_events) {
		struct event ev = {};
		ev.ts = p->now;
		ev.bytes = st->bytes;
		__builtin_memcpy(ev.a, p->src.a, 16);
		ev.reason = st->flagged;
		ev.score = st->score;
		ev.strikes = b.strikes;
		ev.ban_secs = secs;
		ev.pkts = st->pkts;
		ev.tcp = st->tcp;
		ev.udp = st->udp;
		ev.icmp = st->icmp;
		ev.syn = st->syn;
		bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
	}

	st->strikes++;
	st->score = 0;
}

/* Stage 7. Returns a counter slot to drop under, or 0 to pass. */
static __always_inline __u32 rate_stage(struct gate_cfg *cfg, struct pkt *p, int exempt)
{
	struct ip_state *st = bpf_map_lookup_elem(&ip_stats, &p->src);
	__u32 flags = cfg->flags;

	if (!st) {
		struct ip_state fresh = {};
		fresh.win_start = p->now;
		count(C_NEW_SRC, 0);

		if (gate_level >= 2 && (flags & F_NEWSRC) && (flags & F_ATTACK) && cfg->newsrc_limit) {
			__u32 zero = 0;
			struct cpu_win *w = bpf_map_lookup_elem(&cpu_wins, &zero);
			if (w) {
				if (p->now - w->newsrc_win >= NSEC) {
					w->newsrc_win = p->now;
					w->newsrc = 0;
				}
				w->newsrc++;
				/* Too many never-seen senders at once: almost always
				 * forged addresses. Real people try again and get in. */
				if (w->newsrc > cfg->newsrc_limit)
					return C_DROP_NEWSRC;
			}
		}
		bpf_map_update_elem(&ip_stats, &p->src, &fresh, BPF_NOEXIST);
		st = bpf_map_lookup_elem(&ip_stats, &p->src);
		if (!st)
			return 0;
	}

	if (p->now - st->win_start >= NSEC) {
		/* The second is over: judge it, then start a new one. */
		__u64 quiet = (p->now - st->win_start) / NSEC;
		__u64 forgive;

		check_limits(cfg, st, exempt);
		if (st->score >= cfg->score_ban && cfg->score_ban) {
			ban_now(cfg, p, st);
			st->flagged = 0;
			st->win_start = p->now;
			st->pkts = st->tcp = st->udp = st->icmp = st->syn = 0;
			st->bytes = 0;
			return C_DROP_RATE;
		}
		/* Points come off for every clean second since, including the
		 * ones the address spent silent. */
		if (st->flagged)
			quiet--;
		if (quiet > 100000)
			quiet = 100000;
		forgive = quiet * cfg->score_decay;
		if (st->score > forgive)
			st->score -= forgive;
		else
			st->score = 0;
		st->flagged = 0;
		st->win_start = p->now;
		st->pkts = st->tcp = st->udp = st->icmp = st->syn = 0;
		st->bytes = 0;
	}

	st->pkts++;
	st->bytes += p->len;
	if (p->proto == IPPROTO_TCP) {
		st->tcp++;
		if ((p->tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN)
			st->syn++;
	} else if (p->proto == IPPROTO_UDP) {
		st->udp++;
	} else if (p->proto == IPPROTO_ICMP || p->proto == IPPROTO_ICMPV6) {
		st->icmp++;
	}

	if (gate_level >= 2 && (flags & F_TOKEN) && cfg->token_rate) {
		if (st->tokens_ts == 0) {
			st->tokens = cfg->token_burst;
			st->tokens_ts = p->now;
		} else {
			__u64 gap = p->now - st->tokens_ts;
			__u64 add;
			if (gap > 10 * NSEC)
				gap = 10 * NSEC;
			add = gap * cfg->token_rate / NSEC;
			if (add) {
				__u64 t = st->tokens + add;
				if (t > cfg->token_burst)
					t = cfg->token_burst;
				st->tokens = t;
				st->tokens_ts = p->now;
			}
		}
		if (st->tokens == 0)
			return C_DROP_TOKEN;
		st->tokens--;
	}

	/* Do not wait for the second to end during a flood: look every 256 packets. */
	if ((st->pkts & 0xff) == 0) {
		check_limits(cfg, st, exempt);
		if (st->score >= cfg->score_ban && cfg->score_ban) {
			ban_now(cfg, p, st);
			return C_DROP_RATE;
		}
	}

	if ((flags & F_ATTACK) && cfg->attack_ip_pps && !exempt && st->pkts > cfg->attack_ip_pps)
		return C_DROP_CAP;

	return 0;
}

SEC("xdp")
int gate_ingress(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	struct pkt p = {};
	struct gate_cfg *cfg;
	struct ban_val *ban;
	__u32 zero = 0, flags, slot;
	int kind, exempt = 0, tracked;

	cfg = bpf_map_lookup_elem(&cfg_map, &zero);
	if (!cfg || !(cfg->flags & F_ENABLED))
		return XDP_PASS; /* no settings yet: stay out of the way */
	flags = cfg->flags;

	/* 1 read */
	p.len = end - data;
	count(C_SEEN, p.len);
	kind = read_packet(data, end, &p, gate_level >= 2);
	if (kind == P_NONIP) {
		count(C_PASS_NONIP, p.len);
		return XDP_PASS;
	}
	if (kind == P_BAD)
		return verdict_drop(cfg, C_DROP_MALFORMED, p.len);
	p.now = bpf_ktime_get_ns();

	if (p.proto == IPPROTO_TCP) {
		count(C_TCP, p.len);
		if ((p.tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN)
			count(C_SYN, p.len);
	} else if (p.proto == IPPROTO_UDP) {
		count(C_UDP, p.len);
	} else if (p.proto == IPPROTO_ICMP || p.proto == IPPROTO_ICMPV6) {
		count(C_ICMP, p.len);
	} else {
		count(C_OTHER, p.len);
	}

	/* Neighbours on the same wire (IPv6 link-local, and the "no address
	 * yet" sender) keep the network itself working. Never touch them. */
	if (p.v6) {
		__u64 hi, lo;
		__builtin_memcpy(&hi, &p.src.a[0], 8);
		__builtin_memcpy(&lo, &p.src.a[8], 8);
		if ((p.src.a[0] == 0xfe && (p.src.a[1] & 0xc0) == 0x80) || (hi == 0 && lo == 0)) {
			count(C_PASS_LOCAL, p.len);
			return XDP_PASS;
		}
	}

	/* 2 allow */
	if (flags & F_HAS_ALLOW) {
		struct lpm_key lk;
		lk.prefixlen = 128;
		__builtin_memcpy(lk.a, p.src.a, 16);
		if (bpf_map_lookup_elem(&allow, &lk)) {
			count(C_PASS_ALLOW, p.len);
			return XDP_PASS;
		}
	}

	/* 3 banned */
	ban = bpf_map_lookup_elem(&bans, &p.src);
	if (ban) {
		if (ban->until == 0 || ban->until > p.now)
			return verdict_drop(cfg, C_DROP_BANNED, p.len);
		bpf_map_delete_elem(&bans, &p.src); /* served its time */
	}
	if (flags & F_HAS_SUBNETS) {
		struct lpm_key lk;
		lk.prefixlen = 128;
		__builtin_memcpy(lk.a, p.src.a, 16);
		ban = bpf_map_lookup_elem(&subnets, &lk);
		if (ban && (ban->until == 0 || ban->until > p.now))
			return verdict_drop(cfg, C_DROP_SUBNET, p.len);
	}

	/* 4 breaker */
	if (gate_level >= 2 && (flags & F_PANIC) && cfg->panic_pps) {
		struct cpu_win *w = bpf_map_lookup_elem(&cpu_wins, &zero);
		if (w) {
			if (p.now - w->panic_win >= NSEC) {
				w->panic_win = p.now;
				w->panic_pkts = 0;
			}
			w->panic_pkts++;
			if (w->panic_pkts > cfg->panic_pps &&
			    bpf_get_prandom_u32() % 100 < cfg->panic_drop_pct)
				return verdict_drop(cfg, C_DROP_PANIC, p.len);
		}
	}

	/* 5 checks */
	if (p.v6) {
		__u64 hi, lo;
		__builtin_memcpy(&hi, &p.src.a[0], 8);
		__builtin_memcpy(&lo, &p.src.a[8], 8);
		if (flags & F_DROP_BOGON) {
			/* multicast as a sender, loopback, or IPv4 dressed up as IPv6 */
			if (p.src.a[0] == 0xff || (hi == 0 && lo == bpf_cpu_to_be64(1)) ||
			    (hi == 0 && p.src.a[8] == 0 && p.src.a[9] == 0 &&
			     p.src.a[10] == 0xff && p.src.a[11] == 0xff))
				return verdict_drop(cfg, C_DROP_BOGON, p.len);
		}
		if ((flags & F_DROP_PRIVATE) && (p.src.a[0] & 0xfe) == 0xfc)
			return verdict_drop(cfg, C_DROP_PRIVATE, p.len);
	} else {
		if ((flags & F_DROP_BOGON) && v4_bogon(&p))
			return verdict_drop(cfg, C_DROP_BOGON, p.len);
		if ((flags & F_DROP_PRIVATE) && v4_private(p.v4src))
			return verdict_drop(cfg, C_DROP_PRIVATE, p.len);
	}
	if (p.frag && ((flags & F_DROP_FRAGS) ||
		       ((flags & F_DROP_FRAGS_ATTACK) && (flags & F_ATTACK))))
		return verdict_drop(cfg, C_DROP_FRAG, p.len);
	if (p.proto == IPPROTO_TCP && p.has_l4 && (flags & F_DROP_BAD_TCP) &&
	    bad_tcp_flags(p.tcp_flags))
		return verdict_drop(cfg, C_DROP_TCPFLAGS, p.len);

	/* 6 reflection */
	tracked = (flags & F_TRACK) != 0;
	if (p.proto == IPPROTO_TCP && p.has_l4) {
		__u8 f = p.tcp_flags;
		if ((f & (TCP_SYN | TCP_ACK)) != TCP_SYN) {
			if (tracked) {
				exempt = asked_for(&p, 0);
				/* "Yes, let's connect" to a call we never made:
				 * someone used our address as a forged sender. */
				if (!exempt && (flags & F_REFLECT) &&
				    (f & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK))
					return verdict_drop(cfg, C_DROP_REFLECT, p.len);
			} else if (!(flags & F_ATTACK) && (f & TCP_ACK) &&
				   bpf_ntohs(p.dport) >= 32768 && bpf_ntohs(p.sport) < 32768) {
				/* No tracking on this kernel: guess that this is an
				 * answer to a download we started. Not trusted
				 * while under attack. */
				exempt = 1;
			}
		}
	} else if (gate_level >= 2 && p.proto == IPPROTO_UDP && p.has_l4 && (flags & F_AMP)) {
		__u16 sport = bpf_ntohs(p.sport);
		int i, hit = 0;

		for (i = 0; i < AMP_SLOTS; i++) {
			if (cfg->amp_port[i] && cfg->amp_port[i] == sport &&
			    p.payload >= cfg->amp_min[i])
				hit = 1;
		}
		/* With tracking, any DNS answer we did not ask for is suspect,
		 * whatever its size. */
		if (tracked && sport == 53 && p.dns_reply)
			hit = 1;
		if (hit && !(tracked && asked_for(&p, FLOW_FRESH)))
			return verdict_drop(cfg, C_DROP_AMP, p.len);
	}

	/* 7 rate */
	if (gate_level >= 1 && (flags & F_RATE)) {
		slot = rate_stage(cfg, &p, exempt);
		if (slot)
			return verdict_drop(cfg, slot, p.len);
	}

	count(C_PASS, p.len);
	return XDP_PASS;
}

/* Takes notes on what this machine sends out. Never drops, never changes
 * a packet. */
SEC("tc")
int gate_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;
	struct pkt p = {};
	struct flow_key k;
	__u64 now, *seen;

	if (read_packet(data, end, &p, 0) != P_OK || !p.has_l4)
		return TCX_NEXT;

	if (p.proto == IPPROTO_TCP) {
		/* only the opening packet of a connection we start */
		if ((p.tcp_flags & (TCP_SYN | TCP_ACK)) != TCP_SYN)
			return TCX_NEXT;
	} else if (p.proto != IPPROTO_UDP) {
		return TCX_NEXT;
	}

	now = bpf_ktime_get_ns();
	flow_key_of(&k, &p.dst, p.dport, p.sport, p.proto);
	seen = bpf_map_lookup_elem(&flows, &k);
	if (seen) {
		if (now - *seen > NSEC)
			*seen = now;
	} else {
		bpf_map_update_elem(&flows, &k, &now, BPF_ANY);
	}
	return TCX_NEXT;
}

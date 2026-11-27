// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_ALEN     6
#define MAX_BACKENDS 64
#define ETH_P_IP     0x0800
#define IP_FRAG_OFF_MASK 0x1FFF

struct lb_key {
	__be32 vip;   // destination virtual IP
	__be16 dport; // service port
	__u8   proto; // TCP or UDP
	__u8   pad;
};

struct lb_backend {
	__u8   mac[ETH_ALEN]; // Backend MAC
	__be16 target_port;   // 0 = keep dport unchanged
	__u32  reserved;
};

struct lb_service {
	__u32 count;                              // active backends
	__u32 rr;                                 // rr cursor
	struct lb_backend backends[MAX_BACKENDS]; // backend pool
};

struct lb_mac {
	__u8 mac[ETH_ALEN]; // LB egress MAC
	__u8 is_set;        // 1 = configured; 0 = keep source MAC untouched
};

struct lb_stats {
	__u64 packets; // TCP/UDP packet seen
	__u64 pass;    // not ours / no L4
	__u64 tx;      // load-balanced
	__u64 drop;    // our VIP but no ready backends
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct lb_key);
	__type(value, struct lb_service);
} lb_services SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct lb_mac);
} lb_mac SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct lb_stats);
} lb_stats SEC(".maps");

static __always_inline __u16 csum16_add(__u16 csum, __u16 addend) {
	csum += addend;
	return csum + (csum < addend);
}

static __always_inline __u16 csum_replace16(__u16 check, __u16 m0, __u16 m1) {
	return ~csum16_add(csum16_add(~check, ~m0), m1);
}

static __always_inline void stats_inc(__u32 off) {
	__u32 key = 0;
	struct lb_stats *st = bpf_map_lookup_elem(&lb_stats, &key);
	if (!st)
		return;
	if (off == 0)
		__sync_fetch_and_add(&st->packets, 1);
	else if (off == 1)
		__sync_fetch_and_add(&st->pass, 1);
	else if (off == 2)
		__sync_fetch_and_add(&st->tx, 1);
	else if (off == 3)
		__sync_fetch_and_add(&st->drop, 1);
}

static __always_inline bool lb_get_mac(__u8 out[ETH_ALEN]) {
	__u32 key = 0;
	struct lb_mac *m = bpf_map_lookup_elem(&lb_mac, &key);
	if (!m || !m->is_set)
		return false;

	__builtin_memcpy(out, m->mac, ETH_ALEN);
	return true;
}

SEC("xdp")
int xdp_lb(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	if (iph->version != 4)
		return XDP_PASS;

	if (iph->frag_off & bpf_htons(IP_FRAG_OFF_MASK))
		return XDP_PASS;

	__u8 proto = iph->protocol;
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return XDP_PASS;

	int ihl = iph->ihl * 4;
	if (ihl < (int)sizeof(*iph))
		return XDP_PASS;

	void *l4 = (void *)iph + ihl;
	if (l4 + 1 > data_end)
		return XDP_PASS;

	__be16 dport;
	if (proto == IPPROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return XDP_PASS;
		dport = tcp->dest;
	} else {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return XDP_PASS;
		dport = udp->dest;
	}

	stats_inc(0);

	struct lb_key key = {
		.vip = iph->daddr,
		.dport = dport,
		.proto = proto,
		.pad = 0,
	};

	struct lb_service *svc = bpf_map_lookup_elem(&lb_services, &key);
	if (!svc) {
		stats_inc(1);
		return XDP_PASS;
	}

	__u32 count = svc->count;
	if (count == 0 || count > MAX_BACKENDS) {
		stats_inc(3);
		return XDP_DROP;
	}

	__u32 rr = svc->rr;
	__sync_fetch_and_add(&svc->rr, 1);
	__u32 idx = rr % count;

	barrier_var(idx);
	if (idx >= MAX_BACKENDS)
		return XDP_DROP;

	struct lb_backend *be = &svc->backends[idx];

	__builtin_memcpy(eth->h_dest, be->mac, ETH_ALEN);

	__u8 src_mac[ETH_ALEN];
	if (lb_get_mac(src_mac))
		__builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);

	__be16 tport = be->target_port ? be->target_port : dport;
	if (tport != dport) {
		if (proto == IPPROTO_TCP) {
			struct tcphdr *tcp = l4;
			__u16 m0 = tcp->dest;
			tcp->dest = tport;
			tcp->check = csum_replace16(tcp->check, m0, tcp->dest);
		} else {
			struct udphdr *udp = l4;
			__u16 m0 = udp->dest;
			udp->dest = tport;
			if (udp->check != 0)
				udp->check = csum_replace16(udp->check, m0, udp->dest);
		}
	}

	stats_inc(2);
	return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";

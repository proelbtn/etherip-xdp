#define KBUILD_MODNAME "dummy"

#include <linux/types.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/ipv6.h>

struct tunnel_flow_t {
  struct in6_addr remote_addr;
  struct in6_addr local_addr;
} __attribute__((packed));

struct tunnel_entry_t {
  __u32 flags;
  struct tunnel_flow_t flow;
  __u32 ifindex;
} __attribute__((packed));

enum stats_key_t {
  STATS_XDP_DROP,
  STATS_XDP_PASS,
  STATS_XDP_REDIRECT,
  STATS_TOO_SHORT_PKTS,
  STATS_NO_ENTRY,
  STATS_LOOKUP_FAILED,
  STATS_NUM
};

struct stats_t {
  __u64 pkts;
  __u64 bytes;
} __attribute__((packed));

BPF_TABLE_PINNED("array", __u32, struct tunnel_entry_t, tunnel_entries, 16, "/sys/fs/bpf/tunnel_entries");

BPF_TABLE_PINNED("hash", struct tunnel_flow_t, __u32, tunnel_lookup_table, 16, "/sys/fs/bpf/tunnel_lookup_table");

BPF_PERCPU_ARRAY(counters, struct stats_t, STATS_NUM);

static inline void increment_counter(int key, struct xdp_md *ctx) {
  struct stats_t *counter = counters.lookup(&key);
  if (counter == NULL) return;

  counter->pkts++;
  counter->bytes += (__u64)(ctx->data_end - ctx->data);

  counters.update(&key, counter);
}

static inline void copy_ipv6_addr(__u32 *dst, __u32 *src) {
  for (int i = 0; i < 4; i++) dst[i] = src[i];
}

static inline void copy_mac_addr(__u8 *dst, __u8 *src) {
  for (int i = 0; i < 6; i++) dst[i] = src[i];
}

static int rewrite_packet(struct xdp_md *ctx, struct tunnel_entry_t *entry, struct bpf_fib_lookup *params) {
  bpf_xdp_adjust_head(ctx, -(int)(sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + 2));

  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
  __u16 *ei = (__u16 *)(ip6 + 1);
  if ((void *)(ei + 1) > data_end) {
    increment_counter(STATS_TOO_SHORT_PKTS, ctx);
    increment_counter(STATS_XDP_DROP, ctx);
    return XDP_DROP;
  }

  *ei = htons(0x3000);

  ip6->version = 6;
  ip6->priority = 0;
  ip6->flow_lbl[0] = ip6->flow_lbl[1] = ip6->flow_lbl[2] = 0;
  ip6->payload_len = htons(data_end - (void *)(ip6 + 1));
  ip6->nexthdr = 97;
  ip6->hop_limit = 255;
  copy_ipv6_addr(ip6->saddr.s6_addr32, entry->flow.local_addr.s6_addr32);
  copy_ipv6_addr(ip6->daddr.s6_addr32, entry->flow.remote_addr.s6_addr32);

  eth->h_proto = htons(ETH_P_IPV6);
  copy_mac_addr(eth->h_source, params->smac);
  copy_mac_addr(eth->h_dest, params->dmac);

  increment_counter(STATS_XDP_REDIRECT, ctx);
  return bpf_redirect(params->ifindex, 0);
}

static int lookup_nexthop(struct xdp_md *ctx, struct tunnel_entry_t *entry) {
  struct bpf_fib_lookup params = {};
	params.family = 10; // AF_INET6
	params.ifindex = 1;

  copy_ipv6_addr(params.ipv6_src, entry->flow.local_addr.s6_addr32);
  copy_ipv6_addr(params.ipv6_dst, entry->flow.remote_addr.s6_addr32);

	int ret = bpf_fib_lookup(ctx, &params, sizeof(params), 0);
	switch (ret) {
    case BPF_FIB_LKUP_RET_NO_NEIGH:
		case BPF_FIB_LKUP_RET_NOT_FWDED:
		case BPF_FIB_LKUP_RET_FWD_DISABLED:
		case BPF_FIB_LKUP_RET_BLACKHOLE:
		case BPF_FIB_LKUP_RET_UNREACHABLE:
		case BPF_FIB_LKUP_RET_PROHIBIT:
		case BPF_FIB_LKUP_RET_FRAG_NEEDED:
		case BPF_FIB_LKUP_RET_UNSUPP_LWT:
      increment_counter(STATS_LOOKUP_FAILED, ctx);
      increment_counter(STATS_XDP_DROP, ctx);
			return XDP_DROP;
	}

	return rewrite_packet(ctx, entry, &params);
}

int entrypoint(struct xdp_md *ctx) {
  __u32 index = ENTRY_INDEX;
  struct tunnel_entry_t *entry;

  entry = tunnel_entries.lookup(&index);
  if (entry == NULL) {
    increment_counter(STATS_NO_ENTRY, ctx);
    increment_counter(STATS_XDP_DROP, ctx);
    return XDP_DROP;
  }

  return lookup_nexthop(ctx, entry);
}

#define KBUILD_MODNAME "dummy"

#include <linux/types.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/ipv6.h>

struct tunnel_flow {
  struct in6_addr src;
  struct in6_addr dst;
};

struct tunnel_entry {
  struct tunnel_flow flow;
  __u32 ifindex;
};

BPF_TABLE_PINNED("array", __u32, struct tunnel_entry, tunnel_entries, 16, "/sys/fs/bpf/tunnel_entries");

BPF_TABLE_PINNED("hash", struct tunnel_flow, __u32, tunnel_lookup_table, 16, "/sys/fs/bpf/tunnel_lookup_table");

static inline void copy_ipv6_addr(__u32 *dst, __u32 *src) {
  for (int i = 0; i < 4; i++) dst[i] = src[i];
}

static inline void copy_mac_addr(__u8 *dst, __u8 *src) {
  for (int i = 0; i < 6; i++) dst[i] = src[i];
}

static int rewrite_packet(struct xdp_md *ctx, struct bpf_fib_lookup *params) {
  bpf_xdp_adjust_head(ctx, -(int)(sizeof(struct ethhdr) + sizeof(struct ipv6hdr)));

  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  struct ipv6hdr *ip6 = (struct ipv6hdr *)(data + 1);
  if ((void *)(ip6 + 1) > data_end) {
    return XDP_DROP;
  }

  ip6->version = 6;
  ip6->priority = 0;
  ip6->flow_lbl[0] = ip6->flow_lbl[1] = ip6->flow_lbl[2] = 0;
  ip6->payload_len = (data_end - (void *)(ip6 + 1));
  ip6->nexthdr = 97;
  ip6->hop_limit = 255;
  copy_ipv6_addr(ip6->saddr.s6_addr32, params->ipv6_src);
  copy_ipv6_addr(ip6->daddr.s6_addr32, params->ipv6_dst);

  eth->h_proto = htons(ETH_P_IPV6);
  copy_mac_addr(eth->h_source, params->smac);
  copy_mac_addr(eth->h_dest, params->dmac);

  return bpf_redirect(params->ifindex, 0);
}

static int lookup_nexthop(struct xdp_md *ctx, struct tunnel_entry *entry) {
  struct bpf_fib_lookup params = {};
	params.family = 10; // AF_INET6
	params.ifindex = 0;

  copy_ipv6_addr(params.ipv6_src, entry->flow.dst.s6_addr32);
  copy_ipv6_addr(params.ipv6_dst, entry->flow.src.s6_addr32);

	int ret = bpf_fib_lookup(ctx, &params, sizeof(params), 0);
	switch (ret) {
		case BPF_FIB_LKUP_RET_NOT_FWDED:
		case BPF_FIB_LKUP_RET_FWD_DISABLED:
		case BPF_FIB_LKUP_RET_BLACKHOLE:
		case BPF_FIB_LKUP_RET_UNREACHABLE:
		case BPF_FIB_LKUP_RET_PROHIBIT:
		case BPF_FIB_LKUP_RET_FRAG_NEEDED:
		case BPF_FIB_LKUP_RET_UNSUPP_LWT:
			return XDP_DROP;
	}

  return XDP_PASS;
	//return rewrite_packet(ctx, &params);
}

int entrypoint(struct xdp_md *ctx) {
  __u32 index = ENTRY_INDEX;
  struct tunnel_entry *entry;

  entry = tunnel_entries.lookup(&index);
  if (entry == NULL) {
    return XDP_DROP;
  }

  return lookup_nexthop(ctx, entry);
}

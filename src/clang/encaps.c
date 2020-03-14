#define KBUILD_MODNAME "dummy"

#include <linux/types.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/ipv6.h>

struct tunnel_flow {
  struct in6_addr remote_addr;
  struct in6_addr local_addr;
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

static int rewrite_packet(struct xdp_md *ctx, struct tunnel_entry *entry, struct bpf_fib_lookup *params) {
  bpf_xdp_adjust_head(ctx, -(int)(sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + 2));

  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
  __u16 *ei = (__u16 *)(ip6 + 1);

  if ((void *)(ei + 1) > data_end) {
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

  int ret = bpf_redirect(params->ifindex, 0);
  bpf_trace_printk("encaps: XDP_REDIRECT to ifindex %d => %d\n", params->ifindex, ret);
  return ret;
}

static int lookup_nexthop(struct xdp_md *ctx, struct tunnel_entry *entry) {
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
      bpf_trace_printk("encaps: lookup failed 2 => %d\n", ret);
			return XDP_DROP;
	}

	return rewrite_packet(ctx, entry, &params);
}

int entrypoint(struct xdp_md *ctx) {
  __u32 index = ENTRY_INDEX;
  struct tunnel_entry *entry;

  entry = tunnel_entries.lookup(&index);
  if (entry == NULL) {
    bpf_trace_printk("encaps: lookup failed\n");
    return XDP_DROP;
  }

  return lookup_nexthop(ctx, entry);
}

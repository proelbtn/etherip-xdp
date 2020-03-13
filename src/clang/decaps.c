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

BPF_TABLE_PINNED("array", __u32, struct tunnel_entry, tunnel_entries, 1024, "/sys/fs/bpf/tunnel_entries");

BPF_TABLE_PINNED("hash", struct tunnel_flow, __u32, tunnel_lookup_table, 1024, "/sys/fs/bpf/tunnel_lookup_table");

static void memcpy(__u8 *dst, __u8 *src, size_t cnt) {
  while (cnt--) *dst = *src;
}


static int process_ip6hdr(struct xdp_md *ctx, struct ethhdr *eth) {
  void *data_end = (void *)(long)ctx->data_end;

  struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
  if ((void *)(ip6 + 1) > data_end) {
    return XDP_PASS;
  }

  if (ip6->nexthdr != 97) return XDP_PASS;

  struct tunnel_flow flow = {};
  memcpy((void *)&flow, (void *)ip6 + 8, 32);

  __u32 *idx = tunnel_lookup_table.lookup(&flow);
  if (idx == NULL) {
    return XDP_PASS;
  }

  struct tunnel_entry *entry = tunnel_entries.lookup(idx);
  if (entry == NULL) {
    return XDP_PASS;
  }

  bpf_xdp_adjust_head(ctx, sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
  
  return bpf_redirect(entry->ifindex, 0);
}


int entrypoint(struct xdp_md *ctx) {
  return XDP_PASS;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = (void *)data;
  if ((void *)(eth + 1) > data_end) {
    return XDP_PASS;
  }

  switch (ntohs(eth->h_proto)) {
    case ETH_P_IP:
      return XDP_PASS; // not implemented
    case ETH_P_IPV6:
      return process_ip6hdr(ctx, eth);
    default:
      return XDP_PASS;
  }
}


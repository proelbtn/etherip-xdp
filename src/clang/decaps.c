#define KBUILD_MODNAME "dummy"

#include <linux/types.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/ipv6.h>

#define IFINDEX_INVALID 0xffffffff

struct tunnel_flow_t {
  struct in6_addr remote_addr;
  struct in6_addr local_addr;
} __attribute__((packed));

enum tunnel_flags_t {
  FLAGS_IS_ACTIVE = 1 << 0,
};

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
  STATS_UNSUPP_PROTOS,
  STATS_INVALID_ETHERIP_HEADER,
  STATS_ENTRY_NOT_ACTIVE,
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

static int process_ip6hdr(struct xdp_md *ctx, struct ethhdr *eth) {
  void *data_end = (void *)(long)ctx->data_end;

  struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
  if ((void *)(ip6 + 1) > data_end) {
    increment_counter(STATS_TOO_SHORT_PKTS, ctx);
    increment_counter(STATS_XDP_DROP, ctx);
    return XDP_DROP;
  }

  if (ip6->nexthdr != 97) {
    increment_counter(STATS_UNSUPP_PROTOS, ctx);
    increment_counter(STATS_XDP_PASS, ctx);
    return XDP_PASS;
  }

  __u16 *ei = (__u16 *)(ip6 + 1);
  if ((void *)(ei + 1) > data_end) {
    increment_counter(STATS_TOO_SHORT_PKTS, ctx);
    increment_counter(STATS_XDP_DROP, ctx);
    return XDP_PASS;
  }

  if (*ei != htons(0x3000)) {
    increment_counter(STATS_INVALID_ETHERIP_HEADER, ctx);
    increment_counter(STATS_XDP_DROP, ctx);
    return XDP_DROP;
  }

  __u32 *idx = tunnel_lookup_table.lookup((void *)ip6 + 8);
  if (idx == NULL) {
    increment_counter(STATS_NO_ENTRY, ctx);
    increment_counter(STATS_XDP_PASS, ctx);
    return XDP_PASS;
  }

  struct tunnel_entry_t *entry = tunnel_entries.lookup(idx);
  if (entry == NULL) {
    increment_counter(STATS_LOOKUP_FAILED, ctx);
    increment_counter(STATS_XDP_DROP, ctx);
    return XDP_DROP;
  }
  
  if (!(entry->flags & FLAGS_IS_ACTIVE)) {
    increment_counter(STATS_ENTRY_NOT_ACTIVE, ctx);
    increment_counter(STATS_XDP_DROP, ctx);
    return XDP_PASS;
  }
  else {
    bpf_xdp_adjust_head(ctx, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + 2);
    increment_counter(STATS_XDP_REDIRECT, ctx);
    return bpf_redirect(entry->ifindex, 0);
  }
}


int entrypoint(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = (void *)data;
  if ((void *)(eth + 1) > data_end) {
    increment_counter(STATS_TOO_SHORT_PKTS, ctx);
    increment_counter(STATS_XDP_DROP, ctx);
    return XDP_DROP;
  }

  switch (ntohs(eth->h_proto)) {
    case ETH_P_IP:
      increment_counter(STATS_UNSUPP_PROTOS, ctx);
      increment_counter(STATS_XDP_PASS, ctx);
      return XDP_PASS;
    case ETH_P_IPV6:
      return process_ip6hdr(ctx, eth);
    default:
      increment_counter(STATS_XDP_PASS, ctx);
      return XDP_PASS;
  }
}


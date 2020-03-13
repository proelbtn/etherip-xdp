#define KBUILD_MODNAME "dummy"

#include <linux/types.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/in6.h>

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

int entrypoint(struct xdp_md *ctx) {
  return XDP_PASS;
}

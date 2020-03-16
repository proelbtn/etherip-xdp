#define KBUILD_MODNAME "dummy"

#include <linux/types.h>
#include <uapi/linux/in6.h>

struct tunnel_flow {
  struct in6_addr remote_addr;
  struct in6_addr local_addr;
} __attribute__((packed));

struct tunnel_entry {
  struct tunnel_flow flow;
  __u32 ifindex;
} __attribute__((packed));

BPF_ARRAY(tunnel_entries, struct tunnel_entry, 16);

BPF_HASH(tunnel_lookup_table, struct tunnel_flow, __u32, 16);

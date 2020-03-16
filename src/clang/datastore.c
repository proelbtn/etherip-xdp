#define KBUILD_MODNAME "dummy"

#include <linux/types.h>
#include <uapi/linux/in6.h>

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

BPF_ARRAY(tunnel_entries, struct tunnel_entry_t, 16);

BPF_HASH(tunnel_lookup_table, struct tunnel_flow_t, __u32, 16);

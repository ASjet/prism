// clang-format off
#include "vmlinux.h"
#include "if_ether.h"
#include "proto.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
// clang-format on

char _license[] SEC("license") = "GPL";

struct proto_key {
  // Re order the fields to make the alignment more compact
  __u8 l2_proto;
  __u8 l4_proto;
  __be16 l3_proto;
#ifdef APPLICATION_PROTOCOL
  __u16 under_l7_proto;
  __u16 l7_proto;
#else
  __u32 top_proto_type;
#endif
};

#ifdef PER_CPU

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, struct proto_key);
  __type(value, __u64);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 256);
} prism_pkt_cnt SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, struct proto_key);
  __type(value, __u64);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 256);
} prism_byte_cnt SEC(".maps");

static __always_inline void incr_map(void* map, const void* key, __u64 value) {
  __u64* cnt = bpf_map_lookup_elem(map, key);
  if (NULL != cnt) {
    *cnt += value;
  } else {
    bpf_map_update_elem(map, key, &value, BPF_NOEXIST);
  }
}

#else

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct proto_key);
  __type(value, __u64);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 256);
} prism_pkt_cnt SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct proto_key);
  __type(value, __u64);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 256);
} prism_byte_cnt SEC(".maps");

static __always_inline void incr_map(void* map, const void* key, __u64 value) {
  if (0 == bpf_map_update_elem(map, key, &value, BPF_NOEXIST)) {
    return;
  }
  __u64* cnt = bpf_map_lookup_elem(map, key);
  if (NULL != cnt) {
    __sync_fetch_and_add(cnt, value);
  }
}

#endif

static __always_inline void count(const void* key, __u64 bytes) {
  incr_map(&prism_pkt_cnt, &key, 1);
  incr_map(&prism_byte_cnt, &key, bytes);
}

static __always_inline struct proto_key build_key(void* start, void* end) {
  struct proto_key key = {0, 0, 0, 0};
  void* cursor = start;

  // Assume the packet is Ethernet
  // TODO: detect the real L2 protocol
  key.l2_proto = L2_P_ETH;
  struct ethhdr* eth = cursor;
  if (((void*)eth + sizeof(*eth)) > end) {
    return key;
  }
  cursor += sizeof(*eth);
  key.l3_proto = bpf_ntohs(eth->h_proto);

  // L3 protocol
  switch (key.l3_proto) {
    case ETH_P_IP: {
    }
      struct iphdr* iph = cursor;
      if ((void*)iph + sizeof(*iph) > end) {
        return key;
      }
      cursor += sizeof(*iph);
      key.l4_proto = iph->protocol;
      break;
    case ETH_P_IPV6: {
    }
      struct ipv6hdr* ip6h = cursor;
      if ((void*)ip6h + sizeof(*ip6h) > end) {
        return key;
      }
      cursor += sizeof(*ip6h);
      key.l4_proto = ip6h->nexthdr;
      break;
    default:
      return key;
  }

  return key;
}

SEC("xdp.prism")
int prism(struct xdp_md* ctx) {
  void* data = (void*)(long)ctx->data;
  void* data_end = (void*)(long)ctx->data_end;
  __u64 len = (__u8*)data_end - (__u8*)data;

  struct proto_key key = build_key(data, data_end);

#ifdef DEBUG
  bpf_printk("prism: meet pkt[%d] %d %d %d", len, key.l2_proto, key.l3_proto,
             key.l4_proto);
#endif

  count(&key, len);
  return XDP_PASS;
}

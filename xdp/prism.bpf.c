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

static __always_inline void count(const void* key, __u64 bytes) {
  __u64* pkt_cnt = bpf_map_lookup_elem(&prism_pkt_cnt, key);
  if (NULL != pkt_cnt) {
    *pkt_cnt += 1;
  }

  __u64* byte_cnt = bpf_map_lookup_elem(&prism_byte_cnt, key);
  if (NULL != byte_cnt) {
    *byte_cnt += bytes;
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

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif

static __always_inline void count(const void* key, __u64 bytes) {
  __u64* pkt_cnt = bpf_map_lookup_elem(&prism_pkt_cnt, key);
  if (NULL != pkt_cnt) {
    lock_xadd(pkt_cnt, 1);
  }

  __u64* byte_cnt = bpf_map_lookup_elem(&prism_byte_cnt, key);
  if (NULL != byte_cnt) {
    lock_xadd(byte_cnt, bytes);
  }
}

#endif

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
  key.l3_proto = eth->h_proto;

  // L3 protocol
  switch (bpf_ntohs(key.l3_proto)) {
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
  if (0 == key.l2_proto) {
    bpf_printk("prism: meet unknown l2 packet with length %d\n", len);
  }
#endif

  count(&key, len);
  return XDP_PASS;
}

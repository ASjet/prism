// clang-format off
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
// clang-format on

char _license[] SEC("license") = "GPL";

SEC("xdp.prism")
int prism(struct xdp_md* ctx) {
  return XDP_PASS;
}

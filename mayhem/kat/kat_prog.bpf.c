/* Known-answer BPF object: two programs, one BTF-defined map, BTF types. */
#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

struct kat_value {
	__u32 a;
	__u64 b;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, struct kat_value);
} kat_map SEC(".maps");

SEC("socket")
int kat_sock(struct __sk_buff *skb)
{
	return skb->len > 64;
}

SEC("xdp")
int kat_xdp(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

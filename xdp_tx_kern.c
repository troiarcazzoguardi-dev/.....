#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} tx_count SEC(".maps");

SEC("xdp")
int xdp_tx_prog(struct xdp_md *ctx){
    __u32 key=0;
    __u64 *val=bpf_map_lookup_elem(&tx_count,&key);
    if(val) __sync_fetch_and_add(val,1);
    return XDP_TX;
}

char _license[] SEC("license")="GPL";

//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6

// Allow sending events to user-space only every 1s
#define RATE_LIMIT_NS 1000000000 // 1 second

// Structure to send data to userspace
struct tcp_metadata {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

// Define a ring buffer map for user-space communication
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); 
} ringbuf_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} ratelimit_map SEC(".maps");

SEC("xdp")
int xdp_tcp_capture(struct xdp_md *ctx) {
    __u64 now = bpf_ktime_get_ns();
    __u32 key = 0;
    __u64 *last_ts;

    // Get the shared data from the map
    last_ts = bpf_map_lookup_elem(&ratelimit_map, &key);
    if (!last_ts) {
		bpf_printk("No timestamp available in the ratelimit_map");
		return XDP_PASS;
    }

    // check the rate limit before doing more work
    if (now - *last_ts < RATE_LIMIT_NS) {
        bpf_printk("Rate limit exceeded - not sending the event to user space.");
        return XDP_PASS;
    }

    // Extract ethernet header
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;  // Not enough data, pass the packet

    // Check if the packet is an IPv4 packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Extract IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;  // Not enough data, pass the packet

    // Check if it's a TCP packet
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Extract TCP header
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;  // Not enough data, pass the packet

    // Prepare the metadata to send to userspace
    struct tcp_metadata *metadata;
    metadata = bpf_ringbuf_reserve(&ringbuf_map, sizeof(*metadata), 0);
    if (!metadata)
        return XDP_PASS;  // Failed to reserve space, pass the packet

    metadata->src_ip = ip->saddr;
    metadata->dst_ip = ip->daddr;
    metadata->src_port = bpf_ntohs(tcp->source);
    metadata->dst_port = bpf_ntohs(tcp->dest);

    // Submit the metadata to the ring buffer
    bpf_ringbuf_submit(metadata, 0);

    // Update last timestamp
    if (bpf_map_update_elem(&ratelimit_map, &key, &now, 0) != 0) {
		bpf_printk("Failed to update rate limit");
    }

    bpf_printk("Submitted event to ringbuffer...");

    return XDP_PASS;  // Pass the packet to the kernel
}

//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6

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

SEC("xdp")
int xdp_tcp_capture(struct xdp_md *ctx) {
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

    return XDP_PASS;  // Pass the packet to the kernel
}

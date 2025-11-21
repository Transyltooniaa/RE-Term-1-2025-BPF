// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ============================
// Config via .rodata
// ============================

// These variables are:
    // placed in the ELF section .rodata
    // treated as read-only by the kernel
    // made available to userspace through the BPF skeleton

    // Packets per second allowed per source IP
const volatile int rate_limit_pps = 1000;
// Token bucket size / burst
const volatile int burst = 200;

// ============================
// Event struct for ring buffer
// ============================

struct event {
    __u32 src_ip;   // IPv4 saddr, network byte order
    __u64 ts_ns;    // timestamp in ns
    __u32 dropped;  // total dropped so far for this IP
};

// ============================
// Maps
// ============================

// Ring buffer to send events to user space
struct {
    // Ring buffer type map
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


// Per-source-IP rate limiter state
struct rate_state {
    __u64 last_ts_ns;  // last time we updated tokens
    __u32 tokens;      // current tokens
    __u32 dropped;     // total dropped
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH); // hash map 
    __uint(max_entries, 16384);
    __type(key, __u32);              // IPv4 src ip
    __type(value, struct rate_state); // per-IP rate limiting state
} rate_map SEC(".maps");

// ============================
// TC ingress program
// ============================

#define TC_ACT_OK   0 // allow packet
#define TC_ACT_SHOT 2 // drop packet
#define ETH_P_IP    0x0800 // IPv4 ethertype this is in big-endian format

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
    // end of packed
    void *data_end = (void *)(long)ctx->data_end;
    // start of packet
    void *data = (void *)(long)ctx->data;

    // ethernet header
    struct ethhdr *l2;

    // ipv4 header
    struct iphdr *l3;

    // Only handle IPv4
    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    __u32 src_ip = l3->saddr;

    // current time in nanoseconds
    __u64 now_ns = bpf_ktime_get_ns();

    // These structs represent per-IP state:
    struct rate_state *st;
    struct rate_state new_st;

    // Lookup per-IP state
    st = bpf_map_lookup_elem(&rate_map, &src_ip);
    if (!st) {
        // First time we see this IP: initialize
        __builtin_memset(&new_st, 0, sizeof(new_st));
        new_st.last_ts_ns = now_ns;
        if (burst > 0)
            new_st.tokens = burst - 1; // consume 1 token for this packet
        new_st.dropped = 0;

        bpf_map_update_elem(&rate_map, &src_ip, &new_st, BPF_ANY);
        return TC_ACT_OK;
    }

    // Refill tokens based on elapsed time
    __u64 elapsed = now_ns - st->last_ts_ns;

    if (rate_limit_pps > 0 && elapsed > 0) {
        
        // tokens_added = elapsed_seconds * rate_limit_pps
        // tokens_added = (elapsed_ns / 1e9) * rate(limit per second)
        __u64 add = (elapsed * (__u64)rate_limit_pps) / 1000000000ULL;

        if (add > 0) {
            __u64 tokens = (__u64)st->tokens + add;
            if (tokens > (__u64)burst)
                // Cap tokens to burst size 
                tokens = burst;
            // Update state
            st->tokens = (__u32)tokens;
            // Update timestamp
            st->last_ts_ns = now_ns;
        }
    }

    // If we have tokens, consume one and allow packet
    if (st->tokens > 0) {
        st->tokens--;
        return TC_ACT_OK;
    }

    // No tokens: drop and emit event
    st->dropped++;

    // Reserve space in ring buffer for event
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->src_ip = src_ip;
        e->ts_ns = now_ns;
        e->dropped = st->dropped;
        // Submit event to ring buffer
        bpf_ringbuf_submit(e, 0);
    }

    // TC_ACT_SHOT
    return TC_ACT_SHOT;
}

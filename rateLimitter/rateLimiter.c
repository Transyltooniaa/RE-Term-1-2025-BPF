// SPDX-License-Identifier: BSD-3-Clause
#include <argp.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <bpf/libbpf.h>

#include "rateLimiter.skel.h"
#include "common_um.h"   // setup(), exiting


// structure definition used for passing event data from the eBPF program to the userspace program (to inform the user about events such as "a packet was dropped for IP X) through a ring buffer.
struct event {
    //32-bit unsigned integer. Holds the source IPv4 address of the packet. 
    __u32 src_ip;    
    // 64-bit unsigned integer.Represents a timestamp in nanoseconds. Usually the time when the packet was rate-limited.
    __u64 ts_ns;

    // 32-bit unsigned integer. Maintains the count of packets dropped so far for the given source IP. 
    __u32 dropped;
};


// global configuration object that holds all runtime parameters for the program.
static struct env {

    // Packets-per-second allowed per source IP.
    int rate;           
    
    // Token bucket size (how many packets can pass in a burst).
    int burst;  
    
    // Whether to print verbose logs. (whether the program should print extra debug or informational messages. (Attached TC program on ens160 (ifindex 5)))
    bool verbose;

    // the network interface name where the rate-limiting eBPF program should attach  
    char ifname[IFNAMSIZ];   
} env = {
    .rate = 1000,
    .burst = 200,
    .verbose = false,
    .ifname = "ens160",
};

const char *argp_program_version = "rateLimiter 1.0";
const char *argp_program_bug_address = "<path@tofile.dev>";
const char argp_program_doc[] =
"TC ingress rate limiter (per-source IPv4)\n"
"\n"
"USAGE: ./rateLimiter [-i IFACE] [-r RATE_PPS] [-b BURST]\n";

static const struct argp_option opts[] = {
    { "iface",  'i', "IFACE", 0, "Interface to attach TC ingress program to (default: ens160)" },
    { "rate",   'r', "PPS",   0, "Allowed packets per second per source IP (default 1000)" },
    { "burst",  'b', "COUNT", 0, "Token bucket size / burst (default 200)" },
    { "verbose",'v', 0,       0, "Verbose logging" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    long val;

    switch (key) {
    case 'i':
        if (strlen(arg) >= sizeof(env.ifname)) {
            fprintf(stderr, "Interface name too long: %s\n", arg);
            argp_usage(state);
        }
        strncpy(env.ifname, arg, sizeof(env.ifname) - 1);
        env.ifname[sizeof(env.ifname) - 1] = '\0';
        break;
    case 'r':
        errno = 0;
        val = strtol(arg, NULL, 10);
        if (errno || val <= 0) {
            fprintf(stderr, "Invalid rate: %s\n", arg);
            argp_usage(state);
        }
        env.rate = (int)val;
        break;
    case 'b':
        errno = 0;
        val = strtol(arg, NULL, 10);
        if (errno || val <= 0) {
            fprintf(stderr, "Invalid burst: %s\n", arg);
            argp_usage(state);
        }
        env.burst = (int)val;
        break;
    case 'v':
        env.verbose = true;
        break;
    case 'h':
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}


// argp is a GNU library that simplifies command-line argument parsing.
static const struct argp argp = {

    // What command-line options exist
    .options = opts,

    // Which function handles each option
    .parser  = parse_arg,

    //.doc = argp_program_doc
    .doc     = argp_program_doc,
};


//This function handles events coming from the eBPF program through the ring buffer.
// Each time the eBPF program reports a rate-limited packet, this function is called.
static int handle_event(void *ctx, void *data, size_t data_sz)
{

/*
This is the callback function passed to `ring_buffer__new()`.  
Whenever the ring buffer receives an event, libbpf calls this function.

- `ctx` → unused user context  
- `data` → pointer to event data sent by eBPF  
- `data_sz` → size of that event
*/

    const struct event *e = data;

    // Creates a temporary buffer to store the ASCII IPv4 string.
    char ipbuf[INET_ADDRSTRLEN];

    // This line takes the 32-bit integer sent by the eBPF program:
    // .s_addr is the field in struct in_addr that holds the IP address in network byte order.
    struct in_addr addr = { .s_addr = e->src_ip };

    // Now addr can be passed to inet_ntop() to convert: binary_IP → dotted_string_format
    const char *ip = inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf));
    if (!ip)
        ip = "<invalid>";

    printf("Rate-limited packet from %s, total dropped for this IP: %u\n",
           ip, e->dropped);
    return 0;
}


// Explicit TC attach using libbpf

//  skel → the loaded eBPF skeleton containing all programs and maps
//  ifname → the network interface name (e.g., `"ens160"`)
static int attach_tc(struct rateLimiter_bpf *skel, const char *ifname)
{

    // Creates a bpf_tc_hook structure and initializes it to zero. [ which network interface to operate on, which attach point (ingress/egress) , what kind of TC hook to create]
    struct bpf_tc_hook hook = {};

    // Creates a `bpf_tc_opts` structure, also zero-initialized. [This structure is passed to `bpf_tc_attach()` and contains: which program file descriptor to attach, options controlling replace/override behavior]
    struct bpf_tc_opts opts = {};

    // will store the numeric index of the network interface
    // will store error codes from libbpf functions
    int ifindex, err = 0;

    // Get the interface index from the interface name
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "if_nametoindex(%s) failed: %s\n",
                ifname, strerror(errno));
        return -1;
    }

    hook.sz = sizeof(hook);
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_INGRESS;

    if (err && err != -EEXIST) {
        fprintf(stderr, "bpf_tc_hook_create failed: %d\n", err);
        return err;
    }

    opts.sz = sizeof(opts);
    // Set the file descriptor of the eBPF program to attach [This is the specific BPF program I want you to attach to TC]
    opts.prog_fd = bpf_program__fd(skel->progs.tc_ingress);


    // libbpf userspace API function.f
    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "bpf_tc_attach failed: %d\n", err);
        return err;
    }

    if (env.verbose)
        printf("Attached TC program on %s (ifindex %d)\n", ifname, ifindex);

    return 0;
}


int main(int argc, char **argv)
{
    // This declares a pointer to a ring_buffer object.
    struct ring_buffer *rb = NULL;

    /* This declares a pointer to our BPF skeleton.
    It represents:
        our compiled BPF program
        all maps
        all global variables (.rodata)
        all program handles
    */
    struct rateLimiter_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (!setup())
        return 1;  

    
    // During build time, libbpf (or bpftool) generates a C file from our .bpf.c program.
    // It produces a structure called: struct rateLimiter_bpf
    // Allocates memory for struct rateLimiter_bpf, Prepares all maps, programs, and sections in memory.
    skel = rateLimiter_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton: %s\n", strerror(errno));
        return 1;
    }

    // pass config into .rodata
    skel->rodata->rate_limit_pps = env.rate;
    skel->rodata->burst = env.burst;


    /*
        Loads the BPF bytecode into the kernel
        Verifies it with the eBPF verifier
        Creates all maps in the kernel
        Loads your BPF program(s) into the kernel
        Returns 0 on success or a negative error code
    */
    err = rateLimiter_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // *** explicit TC attach instead of auto-attach ***
    err = attach_tc(skel, env.ifname);
    if (err)
        goto cleanup;

    // Create a ring buffer to receive events from the kernel 
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("Rate limiter started on %s: %d pps per source IP, burst %d\n",
           env.ifname, env.rate, env.burst);
    printf("Press Ctrl-C to exit.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    rateLimiter_bpf__destroy(skel);
    return -err;
}

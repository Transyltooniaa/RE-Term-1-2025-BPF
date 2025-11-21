#include "common_um.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

// Global flag checked by main loop.
// Marked volatile + sig_atomic_t to ensure it is safe to write from a signal handler.
volatile sig_atomic_t exiting = 0;

/*
 * Signal handler for SIGINT and SIGTERM.
 * Called asynchronously when the user presses Ctrl-C or when the process
 * receives a termination request.
 *
 * Only sets a global flag because signal handlers must do the absolute minimum:
 * no heap allocation, no printf, no locks.
 */
static void handle_signal(int signo)
{
    (void)signo;     // signo unused; cast prevents compiler warnings
    exiting = 1;     // indicate that the program should shut down
}

/*
 * Raises RLIMIT_MEMLOCK to infinity.
 *
 * eBPF programs and maps require locked memory (non-swappable memory).
 * Older kernels required increasing this limit; without it, loading BPF maps
 * could fail with EPERM or ENOMEM.
 *
 * Modern libbpf may still call this for compatibility reasons.
 */
static bool bump_memlock_rlimit(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,   // soft limit
        .rlim_max = RLIM_INFINITY,   // hard limit
    };

    // Request the kernel to allow unlimited locked memory.
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK: %s\n",
                strerror(errno));
        return false;
    }
    return true;
}

/*
 * Performs common setup for all userspace eBPF programs:
 *
 * 1. Enables strict libbpf mode (more errors, fewer silent fallbacks).
 * 2. Raises RLIMIT_MEMLOCK for older kernels.
 * 3. Installs clean shutdown signal handlers.
 *
 * Returns true if everything succeeded.
 */
bool setup(void)
{
    // Turn on strict checks in libbpf to detect subtle or deprecated usage.
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    // Ensure BPF maps/programs can allocate locked memory.
    if (!bump_memlock_rlimit())
        return false;

    // Register Ctrl-C (SIGINT) handler.
    if (signal(SIGINT, handle_signal) == SIG_ERR) {
        perror("signal(SIGINT)");
        return false;
    }

    // Register "kill" signal (SIGTERM) handler.
    if (signal(SIGTERM, handle_signal) == SIG_ERR) {
        perror("signal(SIGTERM)");
        return false;
    }

    return true;
}

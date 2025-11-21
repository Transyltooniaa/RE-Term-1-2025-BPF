// common_um.h
#ifndef __COMMON_UM_H
#define __COMMON_UM_H

#include <signal.h>
#include <stdbool.h>

extern volatile sig_atomic_t exiting;

/*
 * setup():
 *  - sets libbpf strict mode
 *  - bumps RLIMIT_MEMLOCK
 *  - installs SIGINT/SIGTERM handlers that flip `exiting`
 *
 * returns true on success, false on failure
 */
bool setup(void);

#endif /* __COMMON_UM_H */

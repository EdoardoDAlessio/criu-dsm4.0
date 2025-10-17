#ifndef DSM_LOG_H
#define DSM_LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include "log.h"   

// ANSI colors
#define RED     "\033[31m"  // SERVER - CLIENT / remote
#define GREEN   "\033[32m"  // HANDLER / local
#define CYAN    "\033[36m"  // UFFD / page faults
#define RESET   "\033[0m"

// logging modes
typedef enum {
    DSM_LOG_INVISIBLE, // completely silent 
    DSM_LOG_EVENT,     // clean, one-line summary
    DSM_LOG_DEBUG      // verbose flow (all internals)
} dsm_log_mode_t;

void dsm_log_verbosity_check(void);
extern dsm_log_mode_t DSM_LOG_MODE;

// source identifiers for color coding
typedef enum {
    DSM_SRC_SERVER,   // remote faults
    DSM_SRC_CLIENT,
    DSM_SRC_HANDLER,  // local faults
    DSM_SRC_UFFD      // page faults / write-protect
} dsm_log_src_t;

// internal helper
static inline void dsm_log(dsm_log_src_t src, int verbose_only, const char *fmt, ...) {
    va_list args;
    const char *color;
    struct timespec ts;

    // Completely silent mode
    if (DSM_LOG_MODE == DSM_LOG_INVISIBLE)
        return;

    // Skip verbose-only messages if not in DEBUG
    if (verbose_only && DSM_LOG_MODE != DSM_LOG_DEBUG)
        return;

    
    switch(src) {
        case DSM_SRC_SERVER:  color = RED; break;
        case DSM_SRC_CLIENT:  color = RED; break;
        case DSM_SRC_HANDLER: color = GREEN; break;
        case DSM_SRC_UFFD:    color = CYAN; break;
        default: color = RESET;
    }

    // timestamp
    
    clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(stderr, "(%02ld.%06ld) ", ts.tv_sec % 100, ts.tv_nsec / 1000);

    
    va_start(args, fmt);
    fprintf(stderr, "%s", color);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, RESET "\n");
    va_end(args);
}

// macros for EVENT / DEBUG per source
#define DSM_EVENT_SERVER(fmt, ...)  dsm_log(DSM_SRC_SERVER, 0, "[DSM-SRV] " fmt, ##__VA_ARGS__)
#define DSM_EVENT_CLIENT(fmt, ...)  dsm_log(DSM_SRC_CLIENT, 0, "[DSM-CLT] " fmt, ##__VA_ARGS__)
#define DSM_EVENT_HANDLER(fmt, ...) dsm_log(DSM_SRC_HANDLER, 0, "[DSM-HND] " fmt, ##__VA_ARGS__)
#define DSM_EVENT_UFFD(fmt, ...)    dsm_log(DSM_SRC_UFFD, 0, "[DSM-UFFD] " fmt, ##__VA_ARGS__)

#define DSM_DEBUG_SERVER(fmt, ...)  dsm_log(DSM_SRC_SERVER, 1, "[DSM-SRV-DBG] " fmt, ##__VA_ARGS__)
#define DSM_DEBUG_CLIENT(fmt, ...)  dsm_log(DSM_SRC_CLIENT, 1, "[DSM-CLT-DBG] " fmt, ##__VA_ARGS__)
#define DSM_DEBUG_HANDLER(fmt, ...) dsm_log(DSM_SRC_HANDLER, 1, "[DSM-HND-DBG] " fmt, ##__VA_ARGS__)
#define DSM_DEBUG_UFFD(fmt, ...)    dsm_log(DSM_SRC_UFFD, 1, "[DSM-UFFD-DBG] " fmt, ##__VA_ARGS__)

#endif

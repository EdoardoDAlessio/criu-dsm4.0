#include "dsm_log.h"
#include "log.h"
#include "dsm.h"

dsm_log_mode_t DSM_LOG_MODE = DSM_LOG_DEBUG; // default fallback

void dsm_log_verbosity_check(void) {
    unsigned int criu_v = log_level;
    pr_info("DSM: current CRIU log verbosity = %u\n", criu_v);

    if(criu_v != 2) DSM_LOG_MODE = DSM_LOG_INVISIBLE;
    else DSM_LOG_MODE = DSM_LOG_DEBUG;
    
    /*
    if (criu_v >= 4) {
        DSM_LOG_MODE = DSM_LOG_DEBUG;
        pr_debug("DSM: DSM_LOG_MODE = DEBUG\n");
    } else if (criu_v == 2) {
        DSM_LOG_MODE = DSM_LOG_INVISIBLE;
        pr_info("DSM: DSM_LOG_MODE = INVISIBLE (no DSM output)\n");
    } else {
        DSM_LOG_MODE = DSM_LOG_EVENT;
        pr_info("DSM: DSM_LOG_MODE = EVENT\n");
    }*/
}

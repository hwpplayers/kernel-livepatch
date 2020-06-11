#ifndef _LIVEPATCH_BSC1171746_H
#define _LIVEPATCH_BSC1171746_H

#if IS_ENABLED(CONFIG_HAVE_HW_BREAKPOINT)

int livepatch_bsc1171746_init(void);
static inline void livepatch_bsc1171746_cleanup(void) {}


struct perf_event;
struct perf_event_attr;

int klpp_modify_user_hw_breakpoint(struct perf_event *bp, struct perf_event_attr *attr);


#else /* !IS_ENABLED(CONFIG_HAVE_HW_BREAKPOINT) */

static inline int livepatch_bsc1171746_init(void) { return 0; }

static inline void livepatch_bsc1171746_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_HAVE_HW_BREAKPOINT) */
#endif /* _LIVEPATCH_BSC1171746_H */

#ifndef _LIVEPATCH_BSC1138264_H
#define _LIVEPATCH_BSC1138264_H

#if IS_ENABLED(CONFIG_PPC64)

int livepatch_bsc1138264_init(void);
static inline void livepatch_bsc1138264_cleanup(void) {}


struct task_struct;
struct mm_struct;

int klp_init_new_context(struct task_struct *tsk, struct mm_struct *mm);

#else /* !IS_ENABLED(CONFIG_PPC64) */

static inline int livepatch_bsc1138264_init(void) { return 0; }

static inline void livepatch_bsc1138264_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_PPC64) */
#endif /* _LIVEPATCH_BSC1138264_H */

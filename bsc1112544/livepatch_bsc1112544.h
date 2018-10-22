#ifndef _LIVEPATCH_BSC1112544_H
#define _LIVEPATCH_BSC1112544_H

#if IS_ENABLED(CONFIG_XEN_BLKDEV_FRONTEND)

int livepatch_bsc1112544_init(void);
void livepatch_bsc1112544_cleanup(void);


struct work_struct;

void klp_blkfront_delay_work(struct work_struct *work);


#else /* !IS_ENABLED(CONFIG_XEN_BLKDEV_FRONTEND) */

static inline int livepatch_bsc1112544_init(void) { return 0; }

static inline void livepatch_bsc1112544_cleanup(void) {}

#define LIVEPATCH_BSC1112544_FUNCS

#endif /* IS_ENABLED(CONFIG_XEN_BLKDEV_FRONTEND) */
#endif /* _LIVEPATCH_BSC1112544_H */

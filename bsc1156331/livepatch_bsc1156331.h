#ifndef _LIVEPATCH_BSC1156331_H
#define _LIVEPATCH_BSC1156331_H

int livepatch_bsc1156331_init(void);
static inline void livepatch_bsc1156331_cleanup(void) {}


struct request_queue;

int klpp_blk_init_allocated_queue(struct request_queue *q);

#endif /* _LIVEPATCH_BSC1156331_H */

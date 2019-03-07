#ifndef _LIVEPATCH_BSC1126284_H
#define _LIVEPATCH_BSC1126284_H

static inline int livepatch_bsc1126284_init(void) { return 0; }
static inline void livepatch_bsc1126284_cleanup(void) {}


struct socket;

int klp_af_alg_release(struct socket *sock);

#endif /* _LIVEPATCH_BSC1126284_H */

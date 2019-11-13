#ifndef _LIVEPATCH_BSC1156317_H
#define _LIVEPATCH_BSC1156317_H

int livepatch_bsc1156317_init(void);
static inline void livepatch_bsc1156317_cleanup(void) {}


struct sock;

int klpp_tcp_connect(struct sock *sk);

#endif /* _LIVEPATCH_BSC1156317_H */

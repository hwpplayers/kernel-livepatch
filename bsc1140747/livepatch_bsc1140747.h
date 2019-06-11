#ifndef _LIVEPATCH_BSC1140747_H
#define _LIVEPATCH_BSC1140747_H

int livepatch_bsc1140747_init(void);
static inline void livepatch_bsc1140747_cleanup(void) {}


struct sock;
struct sk_buff;

int klp_tcp_fragment(struct sock *sk, struct sk_buff *skb, u32 len,
		     unsigned int mss_now, gfp_t gfp);

#endif /* _LIVEPATCH_BSC1140747_H */

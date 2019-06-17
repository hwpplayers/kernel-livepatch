#ifndef _LIVEPATCH_BSC1137597_H
#define _LIVEPATCH_BSC1137597_H

int livepatch_bsc1137597_init(void);
static inline void livepatch_bsc1137597_cleanup(void) {}


struct sock;
struct tcp_sack_block;
struct tcp_sacktag_state;

struct sk_buff *
klp_tcp_sacktag_walk(struct sk_buff *skb, struct sock *sk,
		     struct tcp_sack_block *next_dup,
		     struct tcp_sacktag_state *state,
		     u32 start_seq, u32 end_seq,
		     bool dup_sack_in);

int klp_tcp_fragment(struct sock *sk, struct sk_buff *skb, u32 len,
		     unsigned int mss_now, gfp_t gfp);

int klp__tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs);

#endif /* _LIVEPATCH_BSC1137597_H */

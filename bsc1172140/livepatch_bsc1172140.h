#ifndef _LIVEPATCH_BSC1172140_H
#define _LIVEPATCH_BSC1172140_H

int livepatch_bsc1172140_init(void);
void livepatch_bsc1172140_cleanup(void);


struct sk_buff;
struct nlmsghdr;
struct nlattr;

int klpp_xfrm_add_policy(struct sk_buff *skb, struct nlmsghdr *nlh,
		struct nlattr **attrs);

int klpp_xfrm_add_acquire(struct sk_buff *skb, struct nlmsghdr *nlh,
		struct nlattr **attrs);

struct xfrm_policy *klpp_xfrm_compile_policy(struct sock *sk, int opt,
					       u8 *data, int len, int *dir);

#endif /* _LIVEPATCH_BSC1172140_H */

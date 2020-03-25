#ifndef _LIVEPATCH_BSC1165631_TIPC_H
#define _LIVEPATCH_BSC1165631_TIPC_H

int livepatch_bsc1165631_tipc_init(void);
void livepatch_bsc1165631_tipc_cleanup(void);


struct net;
struct sk_buff;
struct tipc_bearer;
struct tipc_media_addr;

int klpp_tipc_udp_send_msg(struct net *net, struct sk_buff *skb,
			     struct tipc_bearer *b,
			     struct tipc_media_addr *addr);

#endif /* _LIVEPATCH_BSC1165631_TIPC_H */

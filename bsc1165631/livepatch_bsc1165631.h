#ifndef _LIVEPATCH_BSC1165631_H
#define _LIVEPATCH_BSC1165631_H

#include "livepatch_bsc1165631_vxlan.h"
#include "livepatch_bsc1165631_geneve.h"
#include "livepatch_bsc1165631_tipc.h"
#include "livepatch_bsc1165631_rdma_rxe.h"

int livepatch_bsc1165631_init(void);
void livepatch_bsc1165631_cleanup(void);


struct net;
struct sock;
struct flowi6;
struct in6_addr;

struct dst_entry *klpp_ip6_dst_lookup_flow(struct net *net,
					   const struct sock *sk,
					   struct flowi6 *fl6,
					   const struct in6_addr *final_dst);

#endif /* _LIVEPATCH_BSC1165631_H */

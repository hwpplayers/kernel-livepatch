#ifndef _LIVEPATCH_BSC1119947_H
#define _LIVEPATCH_BSC1119947_H

#include "livepatch_bsc1119947_sunrpc.h"
#include "livepatch_bsc1119947_auth_rpcgss.h"
#include "livepatch_bsc1119947_nfsv4.h"

int livepatch_bsc1119947_init(void);
void livepatch_bsc1119947_cleanup(void);


struct svc_rqst;

struct net *klp_svc_net(struct svc_rqst *rqstp);
void klp_shadow_rq_bc_net_set(struct svc_rqst *rqstp, struct net *net);
void klp_shadow_rq_bc_net_destroy(struct svc_rqst *rqstp);

#endif /* _LIVEPATCH_BSC1119947_H */

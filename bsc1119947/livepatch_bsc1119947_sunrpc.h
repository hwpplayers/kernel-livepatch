#ifndef _LIVEPATCH_BSC1119947_SUNRPC_H
#define _LIVEPATCH_BSC1119947_SUNRPC_H

int livepatch_bsc1119947_sunrpc_init(void);
void livepatch_bsc1119947_sunrpc_cleanup(void);


struct svc_serv;
struct rpc_rqst;
struct svc_rqst;

int klp_bc_svc_process(struct svc_serv *serv, struct rpc_rqst *req,
		       struct svc_rqst *rqstp);

#endif /* _LIVEPATCH_BSC1119947_SUNRPC_H */

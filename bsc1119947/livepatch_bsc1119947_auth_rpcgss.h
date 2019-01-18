#ifndef _LIVEPATCH_BSC1119947_AUTH_RPCGSS_H
#define _LIVEPATCH_BSC1119947_AUTH_RPCGSS_H

int livepatch_bsc1119947_auth_rpcgss_init(void);
void livepatch_bsc1119947_auth_rpcgss_cleanup(void);


struct svc_rqst;

int klp_svcauth_gss_accept(struct svc_rqst *rqstp, __be32 *authp);
int klp_svcauth_gss_release(struct svc_rqst *rqstp);

#endif /* _LIVEPATCH_BSC1119947_AUTH_RPCGSS_H */

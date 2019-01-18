#ifndef _LIVEPATCH_BSC1119947_NFSV4_H
#define _LIVEPATCH_BSC1119947_NFSV4_H

int livepatch_bsc1119947_nfsv4_init(void);
void livepatch_bsc1119947_nfsv4_cleanup(void);


struct svc_rqst;

__be32 klp_nfs4_callback_compound(struct svc_rqst *rqstp, void *argp,
				  void *resp);

#endif /* _LIVEPATCH_BSC1119947_NFSV4_H */

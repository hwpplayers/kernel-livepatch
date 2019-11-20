#ifndef _LIVEPATCH_BSC1156320_H
#define _LIVEPATCH_BSC1156320_H

int livepatch_bsc1156320_init(void);
void livepatch_bsc1156320_cleanup(void);


struct svc_rqst;
struct nfsd4_compound_state;

struct svc_rqst;
struct nfsd4_compound_state;

struct ____klp_stateid;
typedef struct ____klp_stateid stateid_t;

__be32
klpp_nfsd4_verify_copy(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
		  stateid_t *src_stateid, struct file **src,
		  stateid_t *dst_stateid, struct file **dst);

#endif /* _LIVEPATCH_BSC1156320_H */

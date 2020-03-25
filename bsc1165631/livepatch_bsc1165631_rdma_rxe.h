#ifndef _LIVEPATCH_BSC1165631_RDMA_RXE_H
#define _LIVEPATCH_BSC1165631_RDMA_RXE_H

#if IS_ENABLED(CONFIG_RDMA_RXE)

int livepatch_bsc1165631_rdma_rxe_init(void);
void livepatch_bsc1165631_rdma_rxe_cleanup(void);


struct rxe_dev;
struct rxe_qp;
struct rxe_av;

struct dst_entry *klpp_rxe_find_route(struct net_device *ndev,
					struct rxe_qp *qp,
					struct rxe_av *av);

#else /* !IS_ENABLED(CONFIG_RDMA_RXE) */

static inline int livepatch_bsc1165631_rdma_rxe_init(void) { return 0; }
static inline void livepatch_bsc1165631_rdma_rxe_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_RDMA_RXE) */
#endif /* _LIVEPATCH_BSC1165631_RDMA_RXE_H */

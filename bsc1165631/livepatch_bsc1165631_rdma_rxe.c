/*
 * livepatch_bsc1165631_rdma_rxe
 *
 * Fix for CVE-2020-1749, bsc#1165631 (rdma_rxe.ko part)
 *
 *  Copyright (c) 2020 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
 *
 *  Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#if IS_ENABLED(CONFIG_RDMA_RXE)

#if !IS_MODULE(CONFIG_RDMA_RXE)
#error "Live patch supports only CONFIG_RDMA_RXE=m"
#endif

#define LIVEPATCHED_MODULE "rdma_rxe"

#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <net/udp_tunnel.h>
#include <net/sch_generic.h>
#include <rdma/ib_addr.h>

/* from drivers/infiniband/sw/rxe/rxe.h */
#undef pr_fmt
#define pr_fmt(fmt) LIVEPATCHED_MODULE ": " fmt

#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_pack.h>
#include <net/sock.h>
#include <net/if_inet6.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <rdma/rdma_user_rxe.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1165631.h"
#include "../kallsyms_relocs.h"


/* from include/rdma/ib_cache.h */
static int (*klpe_ib_get_cached_gid)(struct ib_device    *device,
		      u8                   port_num,
		      int                  index,
		      union ib_gid        *gid,
		      struct ib_gid_attr  *attr);


/* from drivers/infiniband/sw/rxe/rxe_net.h */
struct rxe_recv_sockets {
	struct socket *sk4;
	struct socket *sk6;
};

static struct rxe_recv_sockets (*klpe_recv_sockets);


/* from drivers/infiniband/sw/rxe/rxe_param.h */
enum rxe_device_param {
	RXE_FW_VER			= 0,
	RXE_MAX_MR_SIZE			= -1ull,
	RXE_PAGE_SIZE_CAP		= 0xfffff000,
	RXE_VENDOR_ID			= 0,
	RXE_VENDOR_PART_ID		= 0,
	RXE_HW_VER			= 0,
	RXE_MAX_QP			= 0x10000,
	RXE_MAX_QP_WR			= 0x4000,
	RXE_MAX_INLINE_DATA		= 400,
	RXE_DEVICE_CAP_FLAGS		= IB_DEVICE_BAD_PKEY_CNTR
					| IB_DEVICE_BAD_QKEY_CNTR
					| IB_DEVICE_AUTO_PATH_MIG
					| IB_DEVICE_CHANGE_PHY_PORT
					| IB_DEVICE_UD_AV_PORT_ENFORCE
					| IB_DEVICE_PORT_ACTIVE_EVENT
					| IB_DEVICE_SYS_IMAGE_GUID
					| IB_DEVICE_RC_RNR_NAK_GEN
					| IB_DEVICE_SRQ_RESIZE
					| IB_DEVICE_MEM_MGT_EXTENSIONS,
	RXE_MAX_SGE			= 32,
	RXE_MAX_SGE_RD			= 32,
	RXE_MAX_CQ			= 16384,
	RXE_MAX_LOG_CQE			= 15,
	RXE_MAX_MR			= 2 * 1024,
	RXE_MAX_PD			= 0x7ffc,
	RXE_MAX_QP_RD_ATOM		= 128,
	RXE_MAX_EE_RD_ATOM		= 0,
	RXE_MAX_RES_RD_ATOM		= 0x3f000,
	RXE_MAX_QP_INIT_RD_ATOM		= 128,
	RXE_MAX_EE_INIT_RD_ATOM		= 0,
	RXE_ATOMIC_CAP			= 1,
	RXE_MAX_EE			= 0,
	RXE_MAX_RDD			= 0,
	RXE_MAX_MW			= 0,
	RXE_MAX_RAW_IPV6_QP		= 0,
	RXE_MAX_RAW_ETHY_QP		= 0,
	RXE_MAX_MCAST_GRP		= 8192,
	RXE_MAX_MCAST_QP_ATTACH		= 56,
	RXE_MAX_TOT_MCAST_QP_ATTACH	= 0x70000,
	RXE_MAX_AH			= 100,
	RXE_MAX_FMR			= 0,
	RXE_MAX_MAP_PER_FMR		= 0,
	RXE_MAX_SRQ			= 960,
	RXE_MAX_SRQ_WR			= 0x4000,
	RXE_MIN_SRQ_WR			= 1,
	RXE_MAX_SRQ_SGE			= 27,
	RXE_MIN_SRQ_SGE			= 1,
	RXE_MAX_FMR_PAGE_LIST_LEN	= 512,
	RXE_MAX_PKEYS			= 64,
	RXE_LOCAL_CA_ACK_DELAY		= 15,

	RXE_MAX_UCONTEXT		= 512,

	RXE_NUM_PORT			= 1,

	RXE_MIN_QP_INDEX		= 16,
	RXE_MAX_QP_INDEX		= 0x00020000,

	RXE_MIN_SRQ_INDEX		= 0x00020001,
	RXE_MAX_SRQ_INDEX		= 0x00040000,

	RXE_MIN_MR_INDEX		= 0x00000001,
	RXE_MAX_MR_INDEX		= 0x00040000,
	RXE_MIN_MW_INDEX		= 0x00040001,
	RXE_MAX_MW_INDEX		= 0x00060000,
	RXE_MAX_PKT_PER_ACK		= 64,

	RXE_MAX_UNACKED_PSNS		= 128,

	/* Max inflight SKBs per queue pair */
	RXE_INFLIGHT_SKBS_PER_QP_HIGH	= 64,
	RXE_INFLIGHT_SKBS_PER_QP_LOW	= 16,

	/* Delay before calling arbiter timer */
	RXE_NSEC_ARB_TIMER_DELAY	= 200,
};


/* from drivers/infiniband/sw/rxe/rxe_pool.h */
enum rxe_pool_flags {
	RXE_POOL_ATOMIC		= BIT(0),
	RXE_POOL_INDEX		= BIT(1),
	RXE_POOL_KEY		= BIT(2),
};

enum rxe_elem_type {
	RXE_TYPE_UC,
	RXE_TYPE_PD,
	RXE_TYPE_AH,
	RXE_TYPE_SRQ,
	RXE_TYPE_QP,
	RXE_TYPE_CQ,
	RXE_TYPE_MR,
	RXE_TYPE_MW,
	RXE_TYPE_MC_GRP,
	RXE_TYPE_MC_ELEM,
	RXE_NUM_TYPES,		/* keep me last */
};

enum rxe_pool_state {
	rxe_pool_invalid,
	rxe_pool_valid,
};

struct rxe_pool_entry {
	struct rxe_pool		*pool;
	struct kref		ref_cnt;
	struct list_head	list;

	/* only used if indexed or keyed */
	struct rb_node		node;
	u32			index;
};

struct rxe_pool {
	struct rxe_dev		*rxe;
	spinlock_t              pool_lock; /* pool spinlock */
	size_t			elem_size;
	struct kref		ref_cnt;
	void			(*cleanup)(struct rxe_pool_entry *obj);
	enum rxe_pool_state	state;
	enum rxe_pool_flags	flags;
	enum rxe_elem_type	type;

	unsigned int		max_elem;
	atomic_t		num_elem;

	/* only used if indexed or keyed */
	struct rb_root		tree;
	unsigned long		*table;
	size_t			table_size;
	u32			max_index;
	u32			min_index;
	u32			last;
	size_t			key_offset;
	size_t			key_size;
};


/* from drivers/infiniband/sw/rxe/rxe_task.h */
struct rxe_task {
	void			*obj;
	struct tasklet_struct	tasklet;
	int			state;
	spinlock_t		state_lock; /* spinlock for task state */
	void			*arg;
	int			(*func)(void *arg);
	int			ret;
	char			name[16];
	bool			destroyed;
};


/* from rivers/infiniband/sw/rxe/rxe_hw_counters.h */
enum rxe_counters {
	RXE_CNT_SENT_PKTS,
	RXE_CNT_RCVD_PKTS,
	RXE_CNT_DUP_REQ,
	RXE_CNT_OUT_OF_SEQ_REQ,
	RXE_CNT_RCV_RNR,
	RXE_CNT_SND_RNR,
	RXE_CNT_RCV_SEQ_ERR,
	RXE_CNT_COMPLETER_SCHED,
	RXE_CNT_RETRY_EXCEEDED,
	RXE_CNT_RNR_RETRY_EXCEEDED,
	RXE_CNT_COMP_RETRY,
	RXE_CNT_SEND_ERR,
	RXE_NUM_OF_COUNTERS
};


/* from drivers/infiniband/sw/rxe/rxe_verbs.h */
struct rxe_sq {
	int			max_wr;
	int			max_sge;
	int			max_inline;
	spinlock_t		sq_lock; /* guard queue */
	struct rxe_queue	*queue;
};

struct rxe_rq {
	int			max_wr;
	int			max_sge;
	spinlock_t		producer_lock; /* guard queue producer */
	spinlock_t		consumer_lock; /* guard queue consumer */
	struct rxe_queue	*queue;
};

enum rxe_qp_state {
	QP_STATE_RESET,
	QP_STATE_INIT,
	QP_STATE_READY,
	QP_STATE_DRAIN,		/* req only */
	QP_STATE_DRAINED,	/* req only */
	QP_STATE_ERROR
};

struct rxe_req_info {
	enum rxe_qp_state	state;
	int			wqe_index;
	u32			psn;
	int			opcode;
	atomic_t		rd_atomic;
	int			wait_fence;
	int			need_rd_atomic;
	int			wait_psn;
	int			need_retry;
	int			noack_pkts;
	struct rxe_task		task;
};

struct rxe_comp_info {
	u32			psn;
	int			opcode;
	int			timeout;
	int			timeout_retry;
	u32			retry_cnt;
	u32			rnr_retry;
	struct rxe_task		task;
};

struct rxe_resp_info {
	enum rxe_qp_state	state;
	u32			msn;
	u32			psn;
	int			opcode;
	int			drop_msg;
	int			goto_error;
	int			sent_psn_nak;
	enum ib_wc_status	status;
	u8			aeth_syndrome;

	/* Receive only */
	struct rxe_recv_wqe	*wqe;

	/* RDMA read / atomic only */
	u64			va;
	struct rxe_mem		*mr;
	u32			resid;
	u32			rkey;
	u64			atomic_orig;

	/* SRQ only */
	struct {
		struct rxe_recv_wqe	wqe;
		struct ib_sge		sge[RXE_MAX_SGE];
	} srq_wqe;

	/* Responder resources. It's a circular list where the oldest
	 * resource is dropped first.
	 */
	struct resp_res		*resources;
	unsigned int		res_head;
	unsigned int		res_tail;
	struct resp_res		*res;
	struct rxe_task		task;
};

struct rxe_qp {
	struct rxe_pool_entry	pelem;
	struct ib_qp		ibqp;
	struct ib_qp_attr	attr;
	unsigned int		valid;
	unsigned int		mtu;
	int			is_user;

	struct rxe_pd		*pd;
	struct rxe_srq		*srq;
	struct rxe_cq		*scq;
	struct rxe_cq		*rcq;

	enum ib_sig_type	sq_sig_type;

	struct rxe_sq		sq;
	struct rxe_rq		rq;

	struct socket		*sk;
	u32			dst_cookie;

	struct rxe_av		pri_av;
	struct rxe_av		alt_av;

	/* list of mcast groups qp has joined (for cleanup) */
	struct list_head	grp_list;
	spinlock_t		grp_lock; /* guard grp_list */

	struct sk_buff_head	req_pkts;
	struct sk_buff_head	resp_pkts;
	struct sk_buff_head	send_pkts;

	struct rxe_req_info	req;
	struct rxe_comp_info	comp;
	struct rxe_resp_info	resp;

	atomic_t		ssn;
	atomic_t		skb_out;
	int			need_req_skb;

	/* Timer for retranmitting packet when ACKs have been lost. RC
	 * only. The requester sets it when it is not already
	 * started. The responder resets it whenever an ack is
	 * received.
	 */
	struct timer_list retrans_timer;
	u64 qp_timeout_jiffies;

	/* Timer for handling RNR NAKS. */
	struct timer_list rnr_nak_timer;

	spinlock_t		state_lock; /* guard requester and completer */

	struct execute_work	cleanup_work;
};

struct rxe_port {
	struct ib_port_attr	attr;
	u16			*pkey_tbl;
	__be64			port_guid;
	__be64			subnet_prefix;
	spinlock_t		port_lock; /* guard port */
	unsigned int		mtu_cap;
	/* special QPs */
	u32			qp_smi_index;
	u32			qp_gsi_index;
};

struct rxe_dev {
	struct ib_device	ib_dev;
	struct ib_device_attr	attr;
	int			max_ucontext;
	int			max_inline_data;
	struct kref		ref_cnt;
	struct mutex	usdev_lock;

	struct net_device	*ndev;

	int			xmit_errors;

	struct rxe_pool		uc_pool;
	struct rxe_pool		pd_pool;
	struct rxe_pool		ah_pool;
	struct rxe_pool		srq_pool;
	struct rxe_pool		qp_pool;
	struct rxe_pool		cq_pool;
	struct rxe_pool		mr_pool;
	struct rxe_pool		mw_pool;
	struct rxe_pool		mc_grp_pool;
	struct rxe_pool		mc_elem_pool;

	spinlock_t		pending_lock; /* guard pending_mmaps */
	struct list_head	pending_mmaps;

	spinlock_t		mmap_offset_lock; /* guard mmap_offset */
	int			mmap_offset;

	u64			stats_counters[RXE_NUM_OF_COUNTERS];

	struct rxe_port		port;
	struct list_head	list;
	struct crypto_shash	*tfm;
};


/* from drivers/infiniband/sw/rxe/rxe_loc.h */
static inline enum ib_qp_type qp_type(struct rxe_qp *qp)
{
	return qp->ibqp.qp_type;
}


/* from drivers/infiniband/sw/rxe/rxe_net.c */
static struct dst_entry *rxe_find_route4(struct net_device *ndev,
				  struct in_addr *saddr,
				  struct in_addr *daddr)
{
	struct rtable *rt;
	struct flowi4 fl = { { 0 } };

	memset(&fl, 0, sizeof(fl));
	fl.flowi4_oif = ndev->ifindex;
	memcpy(&fl.saddr, saddr, sizeof(*saddr));
	memcpy(&fl.daddr, daddr, sizeof(*daddr));
	fl.flowi4_proto = IPPROTO_UDP;

	rt = ip_route_output_key(&init_net, &fl);
	if (IS_ERR(rt)) {
		pr_err_ratelimited("no route to %pI4\n", &daddr->s_addr);
		return NULL;
	}

	return &rt->dst;
}

#if IS_ENABLED(CONFIG_IPV6)
static struct dst_entry *klpp_rxe_find_route6(struct net_device *ndev,
					 struct in6_addr *saddr,
					 struct in6_addr *daddr)
{
	struct dst_entry *ndst;
	struct flowi6 fl6 = { { 0 } };

	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_oif = ndev->ifindex;
	memcpy(&fl6.saddr, saddr, sizeof(*saddr));
	memcpy(&fl6.daddr, daddr, sizeof(*daddr));
	fl6.flowi6_proto = IPPROTO_UDP;

	/*
	 * Fix CVE-2020-1749
	 *  -5 lines, +7 lines
	 */
	ndst = klpp_ip6_dst_lookup_flow(sock_net((*klpe_recv_sockets).sk6->sk),
					(*klpe_recv_sockets).sk6->sk, &fl6,
					NULL);
	if (unlikely(IS_ERR(ndst))) {
		pr_err_ratelimited("no route to %pI6\n", daddr);
		return NULL;
	}

	if (unlikely(ndst->error)) {
		pr_err("no route to %pI6\n", daddr);
		goto put;
	}

	return ndst;
put:
	dst_release(ndst);
	return NULL;
}

#else
#error "klp-ccp: non-taken branch"
#endif

static struct net_device *klpr_rxe_netdev_from_av(struct rxe_dev *rxe,
					     int port_num,
					     struct rxe_av *av)
{
	union ib_gid gid;
	struct ib_gid_attr attr;
	struct net_device *ndev = rxe->ndev;

	if ((*klpe_ib_get_cached_gid)(&rxe->ib_dev, port_num, av->grh.sgid_index,
			      &gid, &attr) == 0 &&
	    attr.ndev && attr.ndev != ndev)
		ndev = attr.ndev;
	else
		/* Only to ensure that caller may call dev_put() */
		dev_hold(ndev);

	return ndev;
}

struct dst_entry *klpp_rxe_find_route(struct rxe_dev *rxe,
					struct rxe_qp *qp,
					struct rxe_av *av)
{
	struct dst_entry *dst = NULL;
	struct net_device *ndev;

	ndev = klpr_rxe_netdev_from_av(rxe, qp->attr.port_num, av);

	if (qp_type(qp) == IB_QPT_RC)
		dst = sk_dst_get(qp->sk->sk);

	if (!dst || !dst_check(dst, qp->dst_cookie)) {
		if (dst)
			dst_release(dst);

		if (av->network_type == RDMA_NETWORK_IPV4) {
			struct in_addr *saddr;
			struct in_addr *daddr;

			saddr = &av->sgid_addr._sockaddr_in.sin_addr;
			daddr = &av->dgid_addr._sockaddr_in.sin_addr;
			dst = rxe_find_route4(ndev, saddr, daddr);
		} else if (av->network_type == RDMA_NETWORK_IPV6) {
			struct in6_addr *saddr6;
			struct in6_addr *daddr6;

			saddr6 = &av->sgid_addr._sockaddr_in6.sin6_addr;
			daddr6 = &av->dgid_addr._sockaddr_in6.sin6_addr;
			dst = klpp_rxe_find_route6(ndev, saddr6, daddr6);
#if IS_ENABLED(CONFIG_IPV6)
			if (dst)
				qp->dst_cookie =
					rt6_get_cookie((struct rt6_info *)dst);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		}
	}

	dev_put(ndev);
	return dst;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "recv_sockets", (void *)&klpe_recv_sockets, "rdma_rxe" },
	{ "ib_get_cached_gid", (void *)&klpe_ib_get_cached_gid, "ib_core" },
};

static int livepatch_bsc1165631_rdma_rxe_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1165631_rdma_rxe_module_nb = {
	.notifier_call = livepatch_bsc1165631_rdma_rxe_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1165631_rdma_rxe_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1165631_rdma_rxe_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1165631_rdma_rxe_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1165631_rdma_rxe_module_nb);
}

#endif /* IS_ENABLED(CONFIG_RDMA_RXE) */

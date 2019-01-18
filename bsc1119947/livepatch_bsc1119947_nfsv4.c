/*
 * livepatch_bsc1119947_nfsv4
 *
 * Fix for CVE-2018-16884, bsc#1119947 -- nfsv4.ko part
 *
 *  Copyright (c) 2019 SUSE
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sunrpc/xdr.h>
#include <linux/sunrpc/svc.h>
#include <linux/nfs4.h>
#include <linux/nfs_fs.h>
#include "livepatch_bsc1119947.h"
#include "kallsyms_relocs.h"

#if !IS_MODULE(CONFIG_NFS_V4)
#error "Live patch supports only CONFIG_NFS_V4=m"
#endif

#if !IS_ENABLED(CONFIG_NFS_V4_1)
#error "Live patch supports only CONFIG_NFS_V4_1=y"
#endif

#if IS_ENABLED(CONFIG_NFS_V4_2)
#error "Live patch supports only CONFIG_NFS_V4_2=n"
#endif

#if !IS_MODULE(CONFIG_NFS_FS)
#error "Live patch supports only CONFIG_NFS_FS=m"
#endif


#define KLP_PATCHED_MODULE "nfsv4"


struct cb_process_state;

/* from fs/nfs/callback_xdr.c */
typedef __be32 (*callback_process_op_t)(void *, void *,
					struct cb_process_state *);
typedef __be32 (*callback_decode_arg_t)(struct svc_rqst *, struct xdr_stream *, void *);
typedef __be32 (*callback_encode_res_t)(struct svc_rqst *, struct xdr_stream *, void *);

struct callback_op {
	callback_process_op_t process_op;
	callback_decode_arg_t decode_args;
	callback_encode_res_t encode_res;
	long res_maxsize;
};



static __be32 * (*klp_xdr_reserve_space)(struct xdr_stream *xdr, size_t nbytes);
static __be32 *(*klp_xdr_encode_opaque)(__be32 *p, const void *ptr,
					unsigned int nbytes);
static __be32 * (*klp_xdr_inline_decode)(struct xdr_stream *xdr, size_t nbytes);
static void (*klp_xdr_init_decode)(struct xdr_stream *xdr, struct xdr_buf *buf,
				   __be32 *p);
static void (*klp_xdr_init_encode)(struct xdr_stream *xdr, struct xdr_buf *buf,
				   __be32 *p);
static void (*klp_nfs_put_client)(struct nfs_client *clp);
static struct callback_op (*klp_callback_ops)[];
static void (*klp_nfs4_free_slot)(struct nfs4_slot_table *tbl,
				  struct nfs4_slot *slot);
static struct nfs_client * (*klp_nfs4_find_client_ident)(struct net *net,
							 int cb_ident);
static int (*klp_check_gss_callback_principal)(struct nfs_client *clp,
					       struct svc_rqst *rqstp);

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "xdr_reserve_space", (void *)&klp_xdr_reserve_space, "sunrpc" },
	{ "xdr_encode_opaque", (void *)&klp_xdr_encode_opaque, "sunrpc" },
	{ "xdr_inline_decode", (void *)&klp_xdr_inline_decode, "sunrpc" },
	{ "xdr_init_decode", (void *)&klp_xdr_init_decode, "sunrpc" },
	{ "xdr_init_encode", (void *)&klp_xdr_init_encode, "sunrpc" },
	{ "nfs_put_client", (void *)&klp_nfs_put_client, "nfs" },
	{ "callback_ops", (void *)&klp_callback_ops, "nfsv4" },
	{ "nfs4_free_slot", (void *)&klp_nfs4_free_slot, "nfsv4" },
	{ "nfs4_find_client_ident", (void *)&klp_nfs4_find_client_ident,
		"nfsv4" },
	{ "check_gss_callback_principal",
		(void *)&klp_check_gss_callback_principal, "nfsv4" },
};



/* from fs/nfs/nfs4session.h */
#define KLP_NFS4_MAX_SLOT_TABLE (1024U)

#define KLP_SLOT_TABLE_SZ DIV_ROUND_UP(KLP_NFS4_MAX_SLOT_TABLE, 8*sizeof(long))

struct nfs4_slot_table {
	struct nfs4_session *session;		/* Parent session */
	struct nfs4_slot *slots;		/* seqid per slot */
	unsigned long   used_slots[KLP_SLOT_TABLE_SZ]; /* used/unused bitmap */
	spinlock_t	slot_tbl_lock;
	struct rpc_wait_queue	slot_tbl_waitq;	/* allocators may wait here */
	wait_queue_head_t	slot_waitq;	/* Completion wait on slot */
	u32		max_slots;		/* # slots in table */
	u32		max_slotid;		/* Max allowed slotid value */
	u32		highest_used_slotid;	/* sent to server on each SEQ.
						 * op for dynamic resizing */
	u32		target_highest_slotid;	/* Server max_slot target */
	u32		server_highest_slotid;	/* Server highest slotid */
	s32		d_target_highest_slotid; /* Derivative */
	s32		d2_target_highest_slotid; /* 2nd derivative */
	unsigned long	generation;		/* Generation counter for
						   target_highest_slotid */
	struct completion complete;
	unsigned long	slot_tbl_state;
};

struct nfs4_session {
	struct nfs4_sessionid		sess_id;
	u32				flags;
	unsigned long			session_state;
	u32				hash_alg;
	u32				ssv_len;

	/* The fore and back channel */
	struct nfs4_channel_attrs	fc_attrs;
	struct nfs4_slot_table		fc_slot_table;
	struct nfs4_channel_attrs	bc_attrs;
	struct nfs4_slot_table		bc_slot_table;
	struct nfs_client		*clp;
};


/* from fs/nfs/callback.h */
enum nfs4_callback_opnum {
	OP_CB_GETATTR = 3,
	OP_CB_RECALL  = 4,
/* Callback operations new to NFSv4.1 */
	OP_CB_LAYOUTRECALL  = 5,
	OP_CB_NOTIFY        = 6,
	OP_CB_PUSH_DELEG    = 7,
	OP_CB_RECALL_ANY    = 8,
	OP_CB_RECALLABLE_OBJ_AVAIL = 9,
	OP_CB_RECALL_SLOT   = 10,
	OP_CB_SEQUENCE      = 11,
	OP_CB_WANTS_CANCELLED = 12,
	OP_CB_NOTIFY_LOCK   = 13,
	OP_CB_NOTIFY_DEVICEID = 14,
/* Callback operations new to NFSv4.2 */
	OP_CB_OFFLOAD = 15,
	OP_CB_ILLEGAL = 10044,
};

struct cb_process_state {
	__be32			drc_status;
	struct nfs_client	*clp;
	struct nfs4_slot	*slot;
	u32			minorversion;
	struct net		*net;
};

struct cb_compound_hdr_arg {
	unsigned int taglen;
	const char *tag;
	unsigned int minorversion;
	unsigned int cb_ident; /* v4.0 callback identifier */
	unsigned nops;
};

struct cb_compound_hdr_res {
	__be32 *status;
	unsigned int taglen;
	const char *tag;
	__be32 *nops;
};


/* from fs/nfs/nfs4_fs.h */
#if defined(CONFIG_NFS_V4_2)
#define KLP_NFS4_MAX_MINOR_VERSION 2
#elif defined(CONFIG_NFS_V4_1)
#define KLP_NFS4_MAX_MINOR_VERSION 1
#else
#define KLP_NFS4_MAX_MINOR_VERSION 0
#endif


/* from include/linux/net/sunrpc/xdr.h */
/* resolve reference to xdr_reserve_space() + xdr_encode_opaque() exports */
static inline ssize_t
klp_xdr_stream_encode_opaque(struct xdr_stream *xdr, const void *ptr,
			     size_t len)
{
	size_t count = sizeof(__u32) + xdr_align_size(len);
	__be32 *p = klp_xdr_reserve_space(xdr, count);

	if (unlikely(!p))
		return -EMSGSIZE;
	klp_xdr_encode_opaque(p, ptr, len);
	return count;
}

/* resolve reference to xdr_inline_decode() export */
static inline ssize_t
klp_xdr_stream_decode_u32(struct xdr_stream *xdr, __u32 *ptr)
{
	const size_t count = sizeof(*ptr);
	__be32 *p = klp_xdr_inline_decode(xdr, count);

	if (unlikely(!p))
		return -EBADMSG;
	*ptr = be32_to_cpup(p);
	return 0;
}

/* resolve reference to xdr_inline_decode() export */
static inline ssize_t
klp_xdr_stream_decode_opaque_inline(struct xdr_stream *xdr, void **ptr,
				    size_t maxlen)
{
	__be32 *p;
	__u32 len;

	*ptr = NULL;
	if (unlikely(klp_xdr_stream_decode_u32(xdr, &len) < 0))
		return -EBADMSG;
	if (len != 0) {
		p = klp_xdr_inline_decode(xdr, len);
		if (unlikely(!p))
			return -EBADMSG;
		if (unlikely(len > maxlen))
			return -EMSGSIZE;
		*ptr = p;
	}
	return len;
}


/* from fs/nfs/callback_xdr.c */
#define KLP_CB_OP_TAGLEN_MAXSZ		(512)

#define KLP_NFS4ERR_RESOURCE_HDR	11050

/* inlined */
static __be32 *klp_read_buf(struct xdr_stream *xdr, size_t nbytes)
{
	__be32 *p;

	p = klp_xdr_inline_decode(xdr, nbytes);
	if (unlikely(p == NULL))
		printk(KERN_WARNING "NFS: NFSv4 callback reply buffer overflowed!\n");
	return p;
}

/* inlined */
static __be32 klp_decode_string(struct xdr_stream *xdr, unsigned int *len,
		const char **str, size_t maxlen)
{
	ssize_t err;

	err = klp_xdr_stream_decode_opaque_inline(xdr, (void **)str, maxlen);
	if (err < 0)
		return cpu_to_be32(NFS4ERR_RESOURCE);
	*len = err;
	return 0;
}

/* inlined */
static __be32 klp_decode_compound_hdr_arg(struct xdr_stream *xdr,
					  struct cb_compound_hdr_arg *hdr)
{
	__be32 *p;
	__be32 status;

	status = klp_decode_string(xdr, &hdr->taglen, &hdr->tag, KLP_CB_OP_TAGLEN_MAXSZ);
	if (unlikely(status != 0))
		return status;
	p = klp_read_buf(xdr, 12);
	if (unlikely(p == NULL))
		return htonl(NFS4ERR_RESOURCE);
	hdr->minorversion = ntohl(*p++);
	/* Check for minor version support */
	if (hdr->minorversion <= KLP_NFS4_MAX_MINOR_VERSION) {
		hdr->cb_ident = ntohl(*p++); /* ignored by v4.1 and v4.2 */
	} else {
		pr_warn_ratelimited("NFS: %s: NFSv4 server callback with "
			"illegal minor version %u!\n",
			__func__, hdr->minorversion);
		return htonl(NFS4ERR_MINOR_VERS_MISMATCH);
	}
	hdr->nops = ntohl(*p);
	return 0;
}

/* inlined */
static __be32 klp_decode_op_hdr(struct xdr_stream *xdr, unsigned int *op)
{
	__be32 *p;
	p = klp_read_buf(xdr, 4);
	if (unlikely(p == NULL))
		return htonl(KLP_NFS4ERR_RESOURCE_HDR);
	*op = ntohl(*p);
	return 0;
}

/* inlined; careful: there are two, incompatible implementations in nfsv4.ko */
static __be32 klp_encode_string(struct xdr_stream *xdr, unsigned int len,
				const char *str)
{
	if (unlikely(klp_xdr_stream_encode_opaque(xdr, str, len) < 0))
		return cpu_to_be32(NFS4ERR_RESOURCE);
	return 0;
}

/* inlined */
static __be32 klp_encode_compound_hdr_res(struct xdr_stream *xdr,
					  struct cb_compound_hdr_res *hdr)
{
	__be32 status;

	hdr->status = klp_xdr_reserve_space(xdr, 4);
	if (unlikely(hdr->status == NULL))
		return htonl(NFS4ERR_RESOURCE);
	status = klp_encode_string(xdr, hdr->taglen, hdr->tag);
	if (unlikely(status != 0))
		return status;
	hdr->nops = klp_xdr_reserve_space(xdr, 4);
	if (unlikely(hdr->nops == NULL))
		return htonl(NFS4ERR_RESOURCE);
	return 0;
}

/* inlined */
static __be32 klp_encode_op_hdr(struct xdr_stream *xdr, uint32_t op, __be32 res)
{
	__be32 *p;
	
	p = klp_xdr_reserve_space(xdr, 8);
	if (unlikely(p == NULL))
		return htonl(KLP_NFS4ERR_RESOURCE_HDR);
	*p++ = htonl(op);
	*p = res;
	return 0;
}

/* inlined */
static __be32
klp_preprocess_nfs41_op(int nop, unsigned int op_nr, struct callback_op **op)
{
	if (op_nr == OP_CB_SEQUENCE) {
		if (nop != 0)
			return htonl(NFS4ERR_SEQUENCE_POS);
	} else {
		if (nop == 0)
			return htonl(NFS4ERR_OP_NOT_IN_SESSION);
	}

	switch (op_nr) {
	case OP_CB_GETATTR:
	case OP_CB_RECALL:
	case OP_CB_SEQUENCE:
	case OP_CB_RECALL_ANY:
	case OP_CB_RECALL_SLOT:
	case OP_CB_LAYOUTRECALL:
	case OP_CB_NOTIFY_DEVICEID:
	case OP_CB_NOTIFY_LOCK:
		*op = &(*klp_callback_ops)[op_nr];
		break;

	case OP_CB_NOTIFY:
	case OP_CB_PUSH_DELEG:
	case OP_CB_RECALLABLE_OBJ_AVAIL:
	case OP_CB_WANTS_CANCELLED:
		return htonl(NFS4ERR_NOTSUPP);

	default:
		return htonl(NFS4ERR_OP_ILLEGAL);
	}

	return htonl(NFS_OK);
}

/* inlined */
static void klp_nfs4_callback_free_slot(struct nfs4_session *session,
		struct nfs4_slot *slot)
{
	struct nfs4_slot_table *tbl = &session->bc_slot_table;

	spin_lock(&tbl->slot_tbl_lock);
	/*
	 * Let the state manager know callback processing done.
	 * A single slot, so highest used slotid is either 0 or -1
	 */
	klp_nfs4_free_slot(tbl, slot);
	spin_unlock(&tbl->slot_tbl_lock);
}

/* inlined */
static void klp_nfs4_cb_free_slot(struct cb_process_state *cps)
{
	if (cps->slot) {
		klp_nfs4_callback_free_slot(cps->clp->cl_session, cps->slot);
		cps->slot = NULL;
	}
}

static __be32
klp_preprocess_nfs42_op(int nop, unsigned int op_nr, struct callback_op **op)
{
	return htonl(NFS4ERR_MINOR_VERS_MISMATCH);
}

/* inlined */
static __be32
klp_preprocess_nfs4_op(unsigned int op_nr, struct callback_op **op)
{
	switch (op_nr) {
	case OP_CB_GETATTR:
	case OP_CB_RECALL:
		*op = &(*klp_callback_ops)[op_nr];
		break;
	default:
		return htonl(NFS4ERR_OP_ILLEGAL);
	}

	return htonl(NFS_OK);
}

/* inlined */
static __be32 klp_process_op(int nop, struct svc_rqst *rqstp,
		struct xdr_stream *xdr_in, void *argp,
		struct xdr_stream *xdr_out, void *resp,
		struct cb_process_state *cps)
{
	struct callback_op *op = &(*klp_callback_ops)[0];
	unsigned int op_nr;
	__be32 status;
	long maxlen;
	__be32 res;

	status = klp_decode_op_hdr(xdr_in, &op_nr);
	if (unlikely(status))
		return status;

	switch (cps->minorversion) {
	case 0:
		status = klp_preprocess_nfs4_op(op_nr, &op);
		break;
	case 1:
		status = klp_preprocess_nfs41_op(nop, op_nr, &op);
		break;
	case 2:
		status = klp_preprocess_nfs42_op(nop, op_nr, &op);
		break;
	default:
		status = htonl(NFS4ERR_MINOR_VERS_MISMATCH);
	}

	if (status == htonl(NFS4ERR_OP_ILLEGAL))
		op_nr = OP_CB_ILLEGAL;
	if (status)
		goto encode_hdr;

	if (cps->drc_status) {
		status = cps->drc_status;
		goto encode_hdr;
	}

	maxlen = xdr_out->end - xdr_out->p;
	if (maxlen > 0 && maxlen < PAGE_SIZE) {
		status = op->decode_args(rqstp, xdr_in, argp);
		if (likely(status == 0))
			status = op->process_op(argp, resp, cps);
	} else
		status = htonl(NFS4ERR_RESOURCE);

encode_hdr:
	res = klp_encode_op_hdr(xdr_out, op_nr, status);
	if (unlikely(res))
		return res;
	if (op->encode_res != NULL && status == 0)
		status = op->encode_res(rqstp, xdr_out, resp);
	return status;
}



/* patched */
__be32 klp_nfs4_callback_compound(struct svc_rqst *rqstp, void *argp,
				  void *resp)
{
	struct cb_compound_hdr_arg hdr_arg = { 0 };
	struct cb_compound_hdr_res hdr_res = { NULL };
	struct xdr_stream xdr_in, xdr_out;
	__be32 *p, status;
	/*
	 * Fix CVE-2018-16884
	 *  +1 line
	 */
	struct net *net = klp_svc_net(rqstp);
	struct cb_process_state cps = {
		.drc_status = 0,
		.clp = NULL,
		/*
		 * Fix CVE-2018-16884
		 *  -1 line, +1 line
		 */
		.net = net,
	};
	unsigned int nops = 0;

	klp_xdr_init_decode(&xdr_in, &rqstp->rq_arg, rqstp->rq_arg.head[0].iov_base);

	p = (__be32*)((char *)rqstp->rq_res.head[0].iov_base + rqstp->rq_res.head[0].iov_len);
	klp_xdr_init_encode(&xdr_out, &rqstp->rq_res, p);

	status = klp_decode_compound_hdr_arg(&xdr_in, &hdr_arg);
	if (status == htonl(NFS4ERR_RESOURCE))
		return rpc_garbage_args;

	if (hdr_arg.minorversion == 0) {
		/*
		 * Fix CVE-2018-16884
		 *  -1 line, +1 line
		 */
		cps.clp = klp_nfs4_find_client_ident(net, hdr_arg.cb_ident);
		if (!cps.clp || !klp_check_gss_callback_principal(cps.clp, rqstp))
			goto out_invalidcred;
	}

	cps.minorversion = hdr_arg.minorversion;
	hdr_res.taglen = hdr_arg.taglen;
	hdr_res.tag = hdr_arg.tag;
	if (klp_encode_compound_hdr_res(&xdr_out, &hdr_res) != 0)
		return rpc_system_err;

	while (status == 0 && nops != hdr_arg.nops) {
		status = klp_process_op(nops, rqstp, &xdr_in,
					argp, &xdr_out, resp, &cps);
		nops++;
	}

	/* Buffer overflow in decode_ops_hdr or encode_ops_hdr. Return
	* resource error in cb_compound status without returning op */
	if (unlikely(status == htonl(KLP_NFS4ERR_RESOURCE_HDR))) {
		status = htonl(NFS4ERR_RESOURCE);
		nops--;
	}

	*hdr_res.status = status;
	*hdr_res.nops = htonl(nops);
	klp_nfs4_cb_free_slot(&cps);
	klp_nfs_put_client(cps.clp);
	return rpc_success;

out_invalidcred:
	pr_warn_ratelimited("NFS: NFSv4 callback contains invalid cred\n");
	return rpc_autherr_badcred;
}



static int livepatch_bsc1119947_nfsv4_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, KLP_PATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1119947_nfsv4_module_nb = {
	.notifier_call = livepatch_bsc1119947_nfsv4_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1119947_nfsv4_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(KLP_PATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1119947_nfsv4_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1119947_nfsv4_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1119947_nfsv4_module_nb);
}

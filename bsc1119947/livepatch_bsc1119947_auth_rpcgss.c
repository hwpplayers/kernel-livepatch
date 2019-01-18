/*
 * livepatch_bsc1119947_auth_rpcgss
 *
 * Fix for CVE-2018-16884, bsc#1119947 -- auth_rpcgss.ko part
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
#include <linux/sunrpc/auth_gss.h>
#include <linux/sunrpc/cache.h>
#include <linux/sunrpc/gss_api.h>
#include <linux/sunrpc/gss_err.h>
#include <linux/sunrpc/debug.h>
#include <net/netns/generic.h>
#include "livepatch_bsc1119947.h"
#include "kallsyms_relocs.h"

#if !IS_MODULE(CONFIG_SUNRPC_GSS)
#error "Live patch supports only CONFIG_SUNRPC_GSS=m"
#endif

#if !IS_MODULE(CONFIG_SUNRPC)
#error "Live patch supports only CONFIG_SUNRPC=m"
#endif

#if !IS_ENABLED(CONFIG_SUNRPC_DEBUG)
#error "Live patch supports only CONFIG_SUNRPC_DEBUG=y"
#endif


#define KLP_PATCHED_MODULE "auth_rpcgss"


static unsigned int *klp_rpc_debug;
static unsigned int *klp_sunrpc_net_id;

struct rsi;
struct gssp_upcall_data;

static struct cache_head *
(*klp_sunrpc_cache_lookup)(struct cache_detail *detail,
			   struct cache_head *key, int hash);
static int (*klp_cache_check)(struct cache_detail *detail,
			      struct cache_head *h,
			      struct cache_req *rqstp);
static void (*klp_sunrpc_cache_unhash)(struct cache_detail *cd,
				       struct cache_head *h);
static void (*klp_xdr_buf_from_iov)(struct kvec *iov, struct xdr_buf *buf);

static int (*klp_xdr_buf_subsegment)(struct xdr_buf *buf,
				     struct xdr_buf *subbuf,
				     unsigned int base, unsigned int len);
static void (*klp_xdr_buf_trim)(struct xdr_buf *buf, unsigned int len);
static int (*klp_read_bytes_from_xdr_buf)(struct xdr_buf *buf,
					  unsigned int base, void *obj,
					  unsigned int len);
static void (*klp_xdr_shift_buf)(struct xdr_buf *buf, size_t len);
static void (*klp_auth_domain_put)(struct auth_domain *dom);
static void (*klp_rsi_free)(struct rsi *rsii);
static int (*klp_gssp_accept_sec_context_upcall)(struct net *net,
						 struct gssp_upcall_data *data);
static int (*klp_gss_proxy_save_rsc)(struct cache_detail *cd,
				     struct gssp_upcall_data *ud,
				     uint64_t *handle);
static void (*klp_gssp_free_upcall_data)(struct gssp_upcall_data *data);
static int (*klp_set_gss_proxy)(struct net *net, int type);
static struct rsc *(*klp_gss_svc_searchbyctx)(struct cache_detail *cd,
					      struct xdr_netobj *handle);
static u32 (*klp_gss_verify_mic)(struct gss_ctx *context_handle,
				 struct xdr_buf *message,
				 struct xdr_netobj *mic_token);
static int (*klp_gss_write_verf)(struct svc_rqst *rqstp, struct gss_ctx *ctx_id,
				 u32 seq);
static u32 (*klp_gss_wrap)(struct gss_ctx *ctx_id, int  offset,
			   struct xdr_buf *buf, struct page **inpages);
static u32 (*klp_gss_unwrap)(struct gss_ctx *ctx_id, int offset,
			     struct xdr_buf *buf);
static rpc_authflavor_t
(*klp_gss_svc_to_pseudoflavor)(struct gss_api_mech *gm, u32 qop, u32 service);
static u32 (*klp_gss_get_mic)(struct gss_ctx *context_handle,
			      struct xdr_buf *message,
			      struct xdr_netobj *mic_token);

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "rpc_debug", (void *)&klp_rpc_debug, "sunrpc" },
	{ "sunrpc_net_id", (void *)&klp_sunrpc_net_id, "sunrpc" },
	{ "sunrpc_cache_lookup", (void *)&klp_sunrpc_cache_lookup, "sunrpc" },
	{ "cache_check", (void *)&klp_cache_check, "sunrpc" },
	{ "sunrpc_cache_unhash", (void *)&klp_sunrpc_cache_unhash, "sunrpc" },
	{ "xdr_buf_from_iov", (void *)&klp_xdr_buf_from_iov, "sunrpc" },
	{ "xdr_buf_subsegment", (void *)&klp_xdr_buf_subsegment, "sunrpc" },
	{ "xdr_buf_trim", (void *)&klp_xdr_buf_trim, "sunrpc" },
	{ "read_bytes_from_xdr_buf", (void *)&klp_read_bytes_from_xdr_buf,
		"sunrpc" },
	{ "xdr_shift_buf", (void *)&klp_xdr_shift_buf, "sunrpc" },
	{ "auth_domain_put", (void *)&klp_auth_domain_put, "sunrpc" },
	{ "rsi_free", (void *)&klp_rsi_free, "auth_rpcgss" },
	{ "gssp_accept_sec_context_upcall",
		(void *)&klp_gssp_accept_sec_context_upcall, "auth_rpcgss" },
	{ "gss_proxy_save_rsc", (void *)&klp_gss_proxy_save_rsc,
		"auth_rpcgss" },
	{ "gssp_free_upcall_data", (void *)&klp_gssp_free_upcall_data,
		"auth_rpcgss" },
	{ "set_gss_proxy", (void *)&klp_set_gss_proxy, "auth_rpcgss" },
	{ "gss_svc_searchbyctx", (void *)&klp_gss_svc_searchbyctx,
		"auth_rpcgss" },
	{ "gss_verify_mic", (void *)&klp_gss_verify_mic, "auth_rpcgss" },
	{ "gss_write_verf", (void *)&klp_gss_write_verf, "auth_rpcgss" },
	{ "gss_wrap", (void *)&klp_gss_wrap, "auth_rpcgss" },
	{ "gss_unwrap", (void *)&klp_gss_unwrap, "auth_rpcgss" },
	{ "gss_svc_to_pseudoflavor", (void *)&klp_gss_svc_to_pseudoflavor,
		"auth_rpcgss" },
	{ "gss_get_mic", (void *)&klp_gss_get_mic, "auth_rpcgss" },
};



/* from include/linux/sunrpc/debug.h */
/* resolve rpc_debug */
#undef ifdebug
# define ifdebug(fac)		if (unlikely((*klp_rpc_debug) & RPCDBG_##fac))


/* from net/sunrpc/netns.h */
struct sunrpc_net {
	struct proc_dir_entry *proc_net_rpc;
	struct cache_detail *ip_map_cache;
	struct cache_detail *unix_gid_cache;
	struct cache_detail *rsc_cache;
	struct cache_detail *rsi_cache;

	struct super_block *pipefs_sb;
	struct rpc_pipe *gssd_dummy;
	struct mutex pipefs_sb_lock;

	struct list_head all_clients;
	spinlock_t rpc_client_lock;

	struct rpc_clnt *rpcb_local_clnt;
	struct rpc_clnt *rpcb_local_clnt4;
	spinlock_t rpcb_clnt_lock;
	unsigned int rpcb_users;
	unsigned int rpcb_is_af_local : 1;

	struct mutex gssp_lock;
	struct rpc_clnt *gssp_clnt;
	int use_gss_proxy;
	int pipe_version;
	atomic_t pipe_users;
	struct proc_dir_entry *use_gssp_proc;
};


/* from net/sunrpc/auth_gss/gss_rpc_xdr.h */
struct gssp_in_token {
	struct page **pages;	/* Array of contiguous pages */
	unsigned int page_base;	/* Start of page data */
	unsigned int page_len;	/* Length of page data */
};


/* from net/sunrpc/auth_gss/gss_rpc_upcall.h */
struct gssp_upcall_data {
	struct xdr_netobj in_handle;
	struct gssp_in_token in_token;
	struct xdr_netobj out_handle;
	struct xdr_netobj out_token;
	struct rpcsec_gss_oid mech_oid;
	struct svc_cred creds;
	int found_creds;
	int major_status;
	int minor_status;
};


/* from net/sunrpc/auth_gss/svcauth_gss.c */
# define RPCDBG_FACILITY	RPCDBG_AUTH

#define	KLP_RSI_HASHBITS	6

struct rsi {
	struct cache_head	h;
	struct xdr_netobj	in_handle, in_token;
	struct xdr_netobj	out_handle, out_token;
	int			major_status, minor_status;
};

/* inlined */
static inline int klp_rsi_hash(struct rsi *item)
{
	return hash_mem(item->in_handle.data, item->in_handle.len, KLP_RSI_HASHBITS)
	     ^ hash_mem(item->in_token.data, item->in_token.len, KLP_RSI_HASHBITS);
}

/* inlined */
static int klp_dup_to_netobj(struct xdr_netobj *dst, char *src, int len)
{
	dst->len = len;
	dst->data = (len ? kmemdup(src, len, GFP_KERNEL) : NULL);
	if (len && !dst->data)
		return -ENOMEM;
	return 0;
}

/* inlined */
static inline int klp_dup_netobj(struct xdr_netobj *dst, struct xdr_netobj *src)
{
	return klp_dup_to_netobj(dst, src->data, src->len);
}

/* inlined */
static struct rsi *klp_rsi_lookup(struct cache_detail *cd, struct rsi *item)
{
	struct cache_head *ch;
	int hash = klp_rsi_hash(item);

	ch = klp_sunrpc_cache_lookup(cd, &item->h, hash);
	if (ch)
		return container_of(ch, struct rsi, h);
	else
		return NULL;
}

#define KLP_GSS_SEQ_WIN	128

struct gss_svc_seq_data {
	/* highest seq number seen so far: */
	int			sd_max;
	/* for i such that sd_max-GSS_SEQ_WIN < i <= sd_max, the i-th bit of
	 * sd_win is nonzero iff sequence number i has been seen already: */
	unsigned long		sd_win[KLP_GSS_SEQ_WIN/BITS_PER_LONG];
	spinlock_t		sd_lock;
};

struct rsc {
	struct cache_head	h;
	struct xdr_netobj	handle;
	struct svc_cred		cred;
	struct gss_svc_seq_data	seqdata;
	struct gss_ctx		*mechctx;
};

/* inlined */
static int
klp_gss_check_seq_num(struct rsc *rsci, int seq_num)
{
	struct gss_svc_seq_data *sd = &rsci->seqdata;

	spin_lock(&sd->sd_lock);
	if (seq_num > sd->sd_max) {
		if (seq_num >= sd->sd_max + KLP_GSS_SEQ_WIN) {
			memset(sd->sd_win,0,sizeof(sd->sd_win));
			sd->sd_max = seq_num;
		} else while (sd->sd_max < seq_num) {
			sd->sd_max++;
			__clear_bit(sd->sd_max % KLP_GSS_SEQ_WIN, sd->sd_win);
		}
		__set_bit(seq_num % KLP_GSS_SEQ_WIN, sd->sd_win);
		goto ok;
	} else if (seq_num <= sd->sd_max - KLP_GSS_SEQ_WIN) {
		goto drop;
	}
	/* sd_max - GSS_SEQ_WIN < seq_num <= sd_max */
	if (__test_and_set_bit(seq_num % KLP_GSS_SEQ_WIN, sd->sd_win))
		goto drop;
ok:
	spin_unlock(&sd->sd_lock);
	return 1;
drop:
	spin_unlock(&sd->sd_lock);
	return 0;
}

/* inlined */
static inline u32 klp_round_up_to_quad(u32 i)
{
	return (i + 3 ) & ~3;
}

/* inlined */
static inline int
klp_svc_safe_getnetobj(struct kvec *argv, struct xdr_netobj *o)
{
	int l;

	if (argv->iov_len < 4)
		return -1;
	o->len = svc_getnl(argv);
	l = klp_round_up_to_quad(o->len);
	if (argv->iov_len < l)
		return -1;
	o->data = argv->iov_base;
	argv->iov_base += l;
	argv->iov_len -= l;
	return 0;
}

/* inlined */
static inline int
klp_svc_safe_putnetobj(struct kvec *resv, struct xdr_netobj *o)
{
	u8 *p;

	if (resv->iov_len + 4 > PAGE_SIZE)
		return -1;
	svc_putnl(resv, o->len);
	p = resv->iov_base + resv->iov_len;
	resv->iov_len += klp_round_up_to_quad(o->len);
	if (resv->iov_len > PAGE_SIZE)
		return -1;
	memcpy(p, o->data, o->len);
	memset(p + o->len, 0, klp_round_up_to_quad(o->len) - o->len);
	return 0;
}

/* inlined */
static int
klp_gss_verify_header(struct svc_rqst *rqstp, struct rsc *rsci,
		      __be32 *rpcstart, struct rpc_gss_wire_cred *gc,
		      __be32 *authp)
{
	struct gss_ctx		*ctx_id = rsci->mechctx;
	struct xdr_buf		rpchdr;
	struct xdr_netobj	checksum;
	u32			flavor = 0;
	struct kvec		*argv = &rqstp->rq_arg.head[0];
	struct kvec		iov;

	/* data to compute the checksum over: */
	iov.iov_base = rpcstart;
	iov.iov_len = (u8 *)argv->iov_base - (u8 *)rpcstart;
	klp_xdr_buf_from_iov(&iov, &rpchdr);

	*authp = rpc_autherr_badverf;
	if (argv->iov_len < 4)
		return SVC_DENIED;
	flavor = svc_getnl(argv);
	if (flavor != RPC_AUTH_GSS)
		return SVC_DENIED;
	if (klp_svc_safe_getnetobj(argv, &checksum))
		return SVC_DENIED;

	if (rqstp->rq_deferred) /* skip verification of revisited request */
		return SVC_OK;
	if (klp_gss_verify_mic(ctx_id, &rpchdr, &checksum) != GSS_S_COMPLETE) {
		*authp = rpcsec_gsserr_credproblem;
		return SVC_DENIED;
	}

	if (gc->gc_seq > MAXSEQ) {
		dprintk("RPC:       svcauth_gss: discarding request with "
				"large sequence number %d\n", gc->gc_seq);
		*authp = rpcsec_gsserr_ctxproblem;
		return SVC_DENIED;
	}
	if (!klp_gss_check_seq_num(rsci, gc->gc_seq)) {
		dprintk("RPC:       svcauth_gss: discarding request with "
				"old sequence number %d\n", gc->gc_seq);
		return SVC_DROP;
	}
	return SVC_OK;
}

/* inlined */
static int
klp_gss_write_null_verf(struct svc_rqst *rqstp)
{
	__be32     *p;

	svc_putnl(rqstp->rq_res.head, RPC_AUTH_NULL);
	p = rqstp->rq_res.head->iov_base + rqstp->rq_res.head->iov_len;
	/* don't really need to check if head->iov_len > PAGE_SIZE ... */
	*p++ = 0;
	if (!xdr_ressize_check(rqstp, p))
		return -1;
	return 0;
}

/* inlined */
static inline int
klp_read_u32_from_xdr_buf(struct xdr_buf *buf, int base, u32 *obj)
{
	__be32  raw;
	int     status;

	status = klp_read_bytes_from_xdr_buf(buf, base, &raw, sizeof(*obj));
	if (status)
		return status;
	*obj = ntohl(raw);
	return 0;
}

/* inlined */
static int
klp_unwrap_integ_data(struct svc_rqst *rqstp, struct xdr_buf *buf, u32 seq,
		      struct gss_ctx *ctx)
{
	int stat = -EINVAL;
	u32 integ_len, maj_stat;
	struct xdr_netobj mic;
	struct xdr_buf integ_buf;

	/* Did we already verify the signature on the original pass through? */
	if (rqstp->rq_deferred)
		return 0;

	integ_len = svc_getnl(&buf->head[0]);
	if (integ_len & 3)
		return stat;
	if (integ_len > buf->len)
		return stat;
	if (klp_xdr_buf_subsegment(buf, &integ_buf, 0, integ_len))
		BUG();
	/* copy out mic... */
	if (klp_read_u32_from_xdr_buf(buf, integ_len, &mic.len))
		BUG();
	if (mic.len > RPC_MAX_AUTH_SIZE)
		return stat;
	mic.data = kmalloc(mic.len, GFP_KERNEL);
	if (!mic.data)
		return stat;
	if (klp_read_bytes_from_xdr_buf(buf, integ_len + 4, mic.data, mic.len))
		goto out;
	maj_stat = klp_gss_verify_mic(ctx, &integ_buf, &mic);
	if (maj_stat != GSS_S_COMPLETE)
		goto out;
	if (svc_getnl(&buf->head[0]) != seq)
		goto out;
	/* trim off the mic and padding at the end before returning */
	klp_xdr_buf_trim(buf, klp_round_up_to_quad(mic.len) + 4);
	stat = 0;
out:
	kfree(mic.data);
	return stat;
}

/* inlined */
static inline int
klp_total_buf_len(struct xdr_buf *buf)
{
	return buf->head[0].iov_len + buf->page_len + buf->tail[0].iov_len;
}

/* inlined */
static void
klp_fix_priv_head(struct xdr_buf *buf, int pad)
{
	if (buf->page_len == 0) {
		/* We need to adjust head and buf->len in tandem in this
		 * case to make svc_defer() work--it finds the original
		 * buffer start using buf->len - buf->head[0].iov_len. */
		buf->head[0].iov_len -= pad;
	}
}

/* inlined */
static int
klp_unwrap_priv_data(struct svc_rqst *rqstp, struct xdr_buf *buf, u32 seq,
		     struct gss_ctx *ctx)
{
	u32 priv_len, maj_stat;
	int pad, saved_len, remaining_len, offset;

	clear_bit(RQ_SPLICE_OK, &rqstp->rq_flags);

	priv_len = svc_getnl(&buf->head[0]);
	if (rqstp->rq_deferred) {
		/* Already decrypted last time through! The sequence number
		 * check at out_seq is unnecessary but harmless: */
		goto out_seq;
	}
	/* buf->len is the number of bytes from the original start of the
	 * request to the end, where head[0].iov_len is just the bytes
	 * not yet read from the head, so these two values are different: */
	remaining_len = klp_total_buf_len(buf);
	if (priv_len > remaining_len)
		return -EINVAL;
	pad = remaining_len - priv_len;
	buf->len -= pad;
	klp_fix_priv_head(buf, pad);

	/* Maybe it would be better to give gss_unwrap a length parameter: */
	saved_len = buf->len;
	buf->len = priv_len;
	maj_stat = klp_gss_unwrap(ctx, 0, buf);
	pad = priv_len - buf->len;
	buf->len = saved_len;
	buf->len -= pad;
	/* The upper layers assume the buffer is aligned on 4-byte boundaries.
	 * In the krb5p case, at least, the data ends up offset, so we need to
	 * move it around. */
	/* XXX: This is very inefficient.  It would be better to either do
	 * this while we encrypt, or maybe in the receive code, if we can peak
	 * ahead and work out the service and mechanism there. */
	offset = buf->head[0].iov_len % 4;
	if (offset) {
		buf->buflen = RPCSVC_MAXPAYLOAD;
		klp_xdr_shift_buf(buf, offset);
		klp_fix_priv_head(buf, pad);
	}
	if (maj_stat != GSS_S_COMPLETE)
		return -EINVAL;
out_seq:
	if (svc_getnl(&buf->head[0]) != seq)
		return -EINVAL;
	return 0;
}

struct gss_svc_data {
	/* decoded gss client cred: */
	struct rpc_gss_wire_cred	clcred;
	/* save a pointer to the beginning of the encoded verifier,
	 * for use in encryption/checksumming in svcauth_gss_release: */
	__be32				*verf_start;
	struct rsc			*rsci;
};

/* inlined */
static inline int
klp_gss_write_init_verf(struct cache_detail *cd, struct svc_rqst *rqstp,
			struct xdr_netobj *out_handle, int *major_status)
{
	struct rsc *rsci;
	int        rc;

	if (*major_status != GSS_S_COMPLETE)
		return klp_gss_write_null_verf(rqstp);
	rsci = klp_gss_svc_searchbyctx(cd, out_handle);
	if (rsci == NULL) {
		*major_status = GSS_S_NO_CONTEXT;
		return klp_gss_write_null_verf(rqstp);
	}
	rc = klp_gss_write_verf(rqstp, rsci->mechctx, KLP_GSS_SEQ_WIN);
	cache_put(&rsci->h, cd);
	return rc;
}

/* inlined */
static inline int
klp_gss_read_common_verf(struct rpc_gss_wire_cred *gc,
			 struct kvec *argv, __be32 *authp,
			 struct xdr_netobj *in_handle)
{
	/* Read the verifier; should be NULL: */
	*authp = rpc_autherr_badverf;
	if (argv->iov_len < 2 * 4)
		return SVC_DENIED;
	if (svc_getnl(argv) != RPC_AUTH_NULL)
		return SVC_DENIED;
	if (svc_getnl(argv) != 0)
		return SVC_DENIED;
	/* Martial context handle and token for upcall: */
	*authp = rpc_autherr_badcred;
	if (gc->gc_proc == RPC_GSS_PROC_INIT && gc->gc_ctx.len != 0)
		return SVC_DENIED;
	if (klp_dup_netobj(in_handle, &gc->gc_ctx))
		return SVC_CLOSE;
	*authp = rpc_autherr_badverf;

	return 0;
}

/* inlined */
static inline int
klp_gss_read_verf(struct rpc_gss_wire_cred *gc,
		  struct kvec *argv, __be32 *authp,
		  struct xdr_netobj *in_handle,
		  struct xdr_netobj *in_token)
{
	struct xdr_netobj tmpobj;
	int res;

	res = klp_gss_read_common_verf(gc, argv, authp, in_handle);
	if (res)
		return res;

	if (klp_svc_safe_getnetobj(argv, &tmpobj)) {
		kfree(in_handle->data);
		return SVC_DENIED;
	}
	if (klp_dup_netobj(in_token, &tmpobj)) {
		kfree(in_handle->data);
		return SVC_CLOSE;
	}

	return 0;
}

/* inlined */
static inline int
klp_gss_read_proxy_verf(struct svc_rqst *rqstp,
			struct rpc_gss_wire_cred *gc, __be32 *authp,
			struct xdr_netobj *in_handle,
			struct gssp_in_token *in_token)
{
	struct kvec *argv = &rqstp->rq_arg.head[0];
	u32 inlen;
	int res;

	res = klp_gss_read_common_verf(gc, argv, authp, in_handle);
	if (res)
		return res;

	inlen = svc_getnl(argv);
	if (inlen > (argv->iov_len + rqstp->rq_arg.page_len))
		return SVC_DENIED;

	in_token->pages = rqstp->rq_pages;
	in_token->page_base = (ulong)argv->iov_base & ~PAGE_MASK;
	in_token->page_len = inlen;

	return 0;
}

/* optimized */
static inline int
klp_gss_write_resv(struct kvec *resv, size_t size_limit,
		   struct xdr_netobj *out_handle, struct xdr_netobj *out_token,
		   int major_status, int minor_status)
{
	if (resv->iov_len + 4 > size_limit)
		return -1;
	svc_putnl(resv, RPC_SUCCESS);
	if (klp_svc_safe_putnetobj(resv, out_handle))
		return -1;
	if (resv->iov_len + 3 * 4 > size_limit)
		return -1;
	svc_putnl(resv, major_status);
	svc_putnl(resv, minor_status);
	svc_putnl(resv, KLP_GSS_SEQ_WIN);
	if (klp_svc_safe_putnetobj(resv, out_token))
		return -1;
	return 0;
}

/* inlined */
static bool klp_use_gss_proxy(struct net *net)
{
	struct sunrpc_net *sn = net_generic(net, (*klp_sunrpc_net_id));

	/* If use_gss_proxy is still undefined, then try to disable it */
	if (sn->use_gss_proxy == -1)
		klp_set_gss_proxy(net, 0);
	return sn->use_gss_proxy;
}

/* optimized */
static __be32 *
klp_svcauth_gss_prepare_to_wrap(struct xdr_buf *resbuf, struct gss_svc_data *gsd)
{
	__be32 *p;
	u32 verf_len;

	p = gsd->verf_start;
	gsd->verf_start = NULL;

	/* If the reply stat is nonzero, don't wrap: */
	if (*(p-1) != rpc_success)
		return NULL;
	/* Skip the verifier: */
	p += 1;
	verf_len = ntohl(*p++);
	p += XDR_QUADLEN(verf_len);
	/* move accept_stat to right place: */
	memcpy(p, p + 2, 4);
	/* Also don't wrap if the accept stat is nonzero: */
	if (*p != rpc_success) {
		resbuf->head[0].iov_len -= 2 * 4;
		return NULL;
	}
	p++;
	return p;
}

/* inlined */
static inline int
klp_svcauth_gss_wrap_resp_integ(struct svc_rqst *rqstp)
{
	struct gss_svc_data *gsd = (struct gss_svc_data *)rqstp->rq_auth_data;
	struct rpc_gss_wire_cred *gc = &gsd->clcred;
	struct xdr_buf *resbuf = &rqstp->rq_res;
	struct xdr_buf integ_buf;
	struct xdr_netobj mic;
	struct kvec *resv;
	__be32 *p;
	int integ_offset, integ_len;
	int stat = -EINVAL;

	p = klp_svcauth_gss_prepare_to_wrap(resbuf, gsd);
	if (p == NULL)
		goto out;
	integ_offset = (u8 *)(p + 1) - (u8 *)resbuf->head[0].iov_base;
	integ_len = resbuf->len - integ_offset;
	BUG_ON(integ_len % 4);
	*p++ = htonl(integ_len);
	*p++ = htonl(gc->gc_seq);
	if (klp_xdr_buf_subsegment(resbuf, &integ_buf, integ_offset, integ_len))
		BUG();
	if (resbuf->tail[0].iov_base == NULL) {
		if (resbuf->head[0].iov_len + RPC_MAX_AUTH_SIZE > PAGE_SIZE)
			goto out_err;
		resbuf->tail[0].iov_base = resbuf->head[0].iov_base
						+ resbuf->head[0].iov_len;
		resbuf->tail[0].iov_len = 0;
	}
	resv = &resbuf->tail[0];
	mic.data = (u8 *)resv->iov_base + resv->iov_len + 4;
	if (klp_gss_get_mic(gsd->rsci->mechctx, &integ_buf, &mic))
		goto out_err;
	svc_putnl(resv, mic.len);
	memset(mic.data + mic.len, 0,
			klp_round_up_to_quad(mic.len) - mic.len);
	resv->iov_len += XDR_QUADLEN(mic.len) << 2;
	/* not strictly required: */
	resbuf->len += XDR_QUADLEN(mic.len) << 2;
	BUG_ON(resv->iov_len > PAGE_SIZE);
out:
	stat = 0;
out_err:
	return stat;
}

/* inlined */
static inline int
klp_svcauth_gss_wrap_resp_priv(struct svc_rqst *rqstp)
{
	struct gss_svc_data *gsd = (struct gss_svc_data *)rqstp->rq_auth_data;
	struct rpc_gss_wire_cred *gc = &gsd->clcred;
	struct xdr_buf *resbuf = &rqstp->rq_res;
	struct page **inpages = NULL;
	__be32 *p, *len;
	int offset;
	int pad;

	p = klp_svcauth_gss_prepare_to_wrap(resbuf, gsd);
	if (p == NULL)
		return 0;
	len = p++;
	offset = (u8 *)p - (u8 *)resbuf->head[0].iov_base;
	*p++ = htonl(gc->gc_seq);
	inpages = resbuf->pages;
	/* XXX: Would be better to write some xdr helper functions for
	 * nfs{2,3,4}xdr.c that place the data right, instead of copying: */

	/*
	 * If there is currently tail data, make sure there is
	 * room for the head, tail, and 2 * RPC_MAX_AUTH_SIZE in
	 * the page, and move the current tail data such that
	 * there is RPC_MAX_AUTH_SIZE slack space available in
	 * both the head and tail.
	 */
	if (resbuf->tail[0].iov_base) {
		BUG_ON(resbuf->tail[0].iov_base >= resbuf->head[0].iov_base
							+ PAGE_SIZE);
		BUG_ON(resbuf->tail[0].iov_base < resbuf->head[0].iov_base);
		if (resbuf->tail[0].iov_len + resbuf->head[0].iov_len
				+ 2 * RPC_MAX_AUTH_SIZE > PAGE_SIZE)
			return -ENOMEM;
		memmove(resbuf->tail[0].iov_base + RPC_MAX_AUTH_SIZE,
			resbuf->tail[0].iov_base,
			resbuf->tail[0].iov_len);
		resbuf->tail[0].iov_base += RPC_MAX_AUTH_SIZE;
	}
	/*
	 * If there is no current tail data, make sure there is
	 * room for the head data, and 2 * RPC_MAX_AUTH_SIZE in the
	 * allotted page, and set up tail information such that there
	 * is RPC_MAX_AUTH_SIZE slack space available in both the
	 * head and tail.
	 */
	if (resbuf->tail[0].iov_base == NULL) {
		if (resbuf->head[0].iov_len + 2*RPC_MAX_AUTH_SIZE > PAGE_SIZE)
			return -ENOMEM;
		resbuf->tail[0].iov_base = resbuf->head[0].iov_base
			+ resbuf->head[0].iov_len + RPC_MAX_AUTH_SIZE;
		resbuf->tail[0].iov_len = 0;
	}
	if (klp_gss_wrap(gsd->rsci->mechctx, offset, resbuf, inpages))
		return -ENOMEM;
	*len = htonl(resbuf->len - offset);
	pad = 3 - ((resbuf->len - offset - 1)&3);
	p = (__be32 *)(resbuf->tail[0].iov_base + resbuf->tail[0].iov_len);
	memset(p, 0, pad);
	resbuf->tail[0].iov_len += pad;
	resbuf->len += pad;
	return 0;
}



/* patched, only caller, svcauth_gss_accept(), also patched. */
static int klp_svcauth_gss_legacy_init(struct svc_rqst *rqstp,
			/*
			 * Fix CVE-2018-16884
			 *  -1 line, +2 lines
			 */
			struct rpc_gss_wire_cred *gc, __be32 *authp,
			struct net *net)
{
	struct kvec *argv = &rqstp->rq_arg.head[0];
	struct kvec *resv = &rqstp->rq_res.head[0];
	struct rsi *rsip, rsikey;
	int ret;
	/*
	 * Fix CVE-2018-16884
	 *  -1 line, +1 line
	 */
	struct sunrpc_net *sn = net_generic(net, (*klp_sunrpc_net_id));

	memset(&rsikey, 0, sizeof(rsikey));
	ret = klp_gss_read_verf(gc, argv, authp,
				&rsikey.in_handle, &rsikey.in_token);
	if (ret)
		return ret;

	/* Perform upcall, or find upcall result: */
	rsip = klp_rsi_lookup(sn->rsi_cache, &rsikey);
	klp_rsi_free(&rsikey);
	if (!rsip)
		return SVC_CLOSE;
	if (klp_cache_check(sn->rsi_cache, &rsip->h, &rqstp->rq_chandle) < 0)
		/* No upcall result: */
		return SVC_CLOSE;

	ret = SVC_CLOSE;
	/* Got an answer to the upcall; use it: */
	if (klp_gss_write_init_verf(sn->rsc_cache, rqstp,
				    &rsip->out_handle, &rsip->major_status))
		goto out;
	if (klp_gss_write_resv(resv, PAGE_SIZE,
			       &rsip->out_handle, &rsip->out_token,
			       rsip->major_status, rsip->minor_status))
		goto out;

	ret = SVC_COMPLETE;
out:
	cache_put(&rsip->h, sn->rsi_cache);
	return ret;
}

/* patched, only caller, svcauth_gss_accept(), also patched. */
static int klp_svcauth_gss_proxy_init(struct svc_rqst *rqstp,
			/*
			 * Fix CVE-2018-16884
			 *  -1 line, +2 lines
			 */
			struct rpc_gss_wire_cred *gc, __be32 *authp,
			struct net *net)
{
	struct kvec *resv = &rqstp->rq_res.head[0];
	struct xdr_netobj cli_handle;
	struct gssp_upcall_data ud;
	uint64_t handle;
	int status;
	int ret;
	/*
	 * Fix CVE-2018-16884
	 *  -1 line
	 */
	struct sunrpc_net *sn = net_generic(net, (*klp_sunrpc_net_id));

	memset(&ud, 0, sizeof(ud));
	ret = klp_gss_read_proxy_verf(rqstp, gc, authp,
				      &ud.in_handle, &ud.in_token);
	if (ret)
		return ret;

	ret = SVC_CLOSE;

	/* Perform synchronous upcall to gss-proxy */
	status = klp_gssp_accept_sec_context_upcall(net, &ud);
	if (status)
		goto out;

	dprintk("RPC:       svcauth_gss: gss major status = %d "
			"minor status = %d\n",
			ud.major_status, ud.minor_status);

	switch (ud.major_status) {
	case GSS_S_CONTINUE_NEEDED:
		cli_handle = ud.out_handle;
		break;
	case GSS_S_COMPLETE:
		status = klp_gss_proxy_save_rsc(sn->rsc_cache, &ud, &handle);
		if (status)
			goto out;
		cli_handle.data = (u8 *)&handle;
		cli_handle.len = sizeof(handle);
		break;
	default:
		ret = SVC_CLOSE;
		goto out;
	}

	/* Got an answer to the upcall; use it: */
	if (klp_gss_write_init_verf(sn->rsc_cache, rqstp,
				    &cli_handle, &ud.major_status))
		goto out;
	if (klp_gss_write_resv(resv, PAGE_SIZE,
			       &cli_handle, &ud.out_token,
			       ud.major_status, ud.minor_status))
		goto out;

	ret = SVC_COMPLETE;
out:
	klp_gssp_free_upcall_data(&ud);
	return ret;
}

/* patched */
int klp_svcauth_gss_accept(struct svc_rqst *rqstp, __be32 *authp)
{
	struct kvec	*argv = &rqstp->rq_arg.head[0];
	struct kvec	*resv = &rqstp->rq_res.head[0];
	u32		crlen;
	struct gss_svc_data *svcdata = rqstp->rq_auth_data;
	struct rpc_gss_wire_cred *gc;
	struct rsc	*rsci = NULL;
	__be32		*rpcstart;
	__be32		*reject_stat = resv->iov_base + resv->iov_len;
	int		ret;
	/*
	 * Fix CVE-2018-16884
	 *  -1 line, +2 lines
	 */
	struct net *net = klp_svc_net(rqstp);
	struct sunrpc_net *sn = net_generic(net, (*klp_sunrpc_net_id));

	dprintk("RPC:       svcauth_gss: argv->iov_len = %zd\n",
			argv->iov_len);

	*authp = rpc_autherr_badcred;
	if (!svcdata)
		svcdata = kmalloc(sizeof(*svcdata), GFP_KERNEL);
	if (!svcdata)
		goto auth_err;
	rqstp->rq_auth_data = svcdata;
	svcdata->verf_start = NULL;
	svcdata->rsci = NULL;
	gc = &svcdata->clcred;

	/* start of rpc packet is 7 u32's back from here:
	 * xid direction rpcversion prog vers proc flavour
	 */
	rpcstart = argv->iov_base;
	rpcstart -= 7;

	/* credential is:
	 *   version(==1), proc(0,1,2,3), seq, service (1,2,3), handle
	 * at least 5 u32s, and is preceded by length, so that makes 6.
	 */

	if (argv->iov_len < 5 * 4)
		goto auth_err;
	crlen = svc_getnl(argv);
	if (svc_getnl(argv) != RPC_GSS_VERSION)
		goto auth_err;
	gc->gc_proc = svc_getnl(argv);
	gc->gc_seq = svc_getnl(argv);
	gc->gc_svc = svc_getnl(argv);
	if (klp_svc_safe_getnetobj(argv, &gc->gc_ctx))
		goto auth_err;
	if (crlen != klp_round_up_to_quad(gc->gc_ctx.len) + 5 * 4)
		goto auth_err;

	if ((gc->gc_proc != RPC_GSS_PROC_DATA) && (rqstp->rq_proc != 0))
		goto auth_err;

	*authp = rpc_autherr_badverf;
	switch (gc->gc_proc) {
	case RPC_GSS_PROC_INIT:
	case RPC_GSS_PROC_CONTINUE_INIT:
		/*
		 * Fix CVE-2018-16884
		 *  -1 line, +1 line
		 */
		if (klp_use_gss_proxy(net))
			/*
			 * Fix CVE-2018-16884
			 *  -1 line, +1 line
			 */
			return klp_svcauth_gss_proxy_init(rqstp, gc, authp, net);
		else
			/*
			 * Fix CVE-2018-16884
			 *  -1 line, +1 line
			 */
			return klp_svcauth_gss_legacy_init(rqstp, gc, authp, net);
	case RPC_GSS_PROC_DATA:
	case RPC_GSS_PROC_DESTROY:
		/* Look up the context, and check the verifier: */
		*authp = rpcsec_gsserr_credproblem;
		rsci = klp_gss_svc_searchbyctx(sn->rsc_cache, &gc->gc_ctx);
		if (!rsci)
			goto auth_err;
		switch (klp_gss_verify_header(rqstp, rsci, rpcstart, gc, authp)) {
		case SVC_OK:
			break;
		case SVC_DENIED:
			goto auth_err;
		case SVC_DROP:
			goto drop;
		}
		break;
	default:
		*authp = rpc_autherr_rejectedcred;
		goto auth_err;
	}

	/* now act upon the command: */
	switch (gc->gc_proc) {
	case RPC_GSS_PROC_DESTROY:
		if (klp_gss_write_verf(rqstp, rsci->mechctx, gc->gc_seq))
			goto auth_err;
		/* Delete the entry from the cache_list and call cache_put */
		klp_sunrpc_cache_unhash(sn->rsc_cache, &rsci->h);
		if (resv->iov_len + 4 > PAGE_SIZE)
			goto drop;
		svc_putnl(resv, RPC_SUCCESS);
		goto complete;
	case RPC_GSS_PROC_DATA:
		*authp = rpcsec_gsserr_ctxproblem;
		svcdata->verf_start = resv->iov_base + resv->iov_len;
		if (klp_gss_write_verf(rqstp, rsci->mechctx, gc->gc_seq))
			goto auth_err;
		rqstp->rq_cred = rsci->cred;
		get_group_info(rsci->cred.cr_group_info);
		*authp = rpc_autherr_badcred;
		switch (gc->gc_svc) {
		case RPC_GSS_SVC_NONE:
			break;
		case RPC_GSS_SVC_INTEGRITY:
			/* placeholders for length and seq. number: */
			svc_putnl(resv, 0);
			svc_putnl(resv, 0);
			if (klp_unwrap_integ_data(rqstp, &rqstp->rq_arg,
						  gc->gc_seq, rsci->mechctx))
				goto garbage_args;
			rqstp->rq_auth_slack = RPC_MAX_AUTH_SIZE;
			break;
		case RPC_GSS_SVC_PRIVACY:
			/* placeholders for length and seq. number: */
			svc_putnl(resv, 0);
			svc_putnl(resv, 0);
			if (klp_unwrap_priv_data(rqstp, &rqstp->rq_arg,
						 gc->gc_seq, rsci->mechctx))
				goto garbage_args;
			rqstp->rq_auth_slack = RPC_MAX_AUTH_SIZE * 2;
			break;
		default:
			goto auth_err;
		}
		svcdata->rsci = rsci;
		cache_get(&rsci->h);
		rqstp->rq_cred.cr_flavor = klp_gss_svc_to_pseudoflavor(
					rsci->mechctx->mech_type,
					GSS_C_QOP_DEFAULT,
					gc->gc_svc);
		ret = SVC_OK;
		goto out;
	}
garbage_args:
	ret = SVC_GARBAGE;
	goto out;
auth_err:
	/* Restore write pointer to its original value: */
	xdr_ressize_check(rqstp, reject_stat);
	ret = SVC_DENIED;
	goto out;
complete:
	ret = SVC_COMPLETE;
	goto out;
drop:
	ret = SVC_CLOSE;
out:
	if (rsci)
		cache_put(&rsci->h, sn->rsc_cache);
	return ret;
}

/* patched */
int klp_svcauth_gss_release(struct svc_rqst *rqstp)
{
	struct gss_svc_data *gsd = (struct gss_svc_data *)rqstp->rq_auth_data;
	struct rpc_gss_wire_cred *gc = &gsd->clcred;
	struct xdr_buf *resbuf = &rqstp->rq_res;
	int stat = -EINVAL;
	/*
	 * Fix CVE-2018-16884
	 *  -1 line, +1 line
	 */
	struct sunrpc_net *sn = net_generic(klp_svc_net(rqstp), (*klp_sunrpc_net_id));

	if (gc->gc_proc != RPC_GSS_PROC_DATA)
		goto out;
	/* Release can be called twice, but we only wrap once. */
	if (gsd->verf_start == NULL)
		goto out;
	/* normally not set till svc_send, but we need it here: */
	/* XXX: what for?  Do we mess it up the moment we call svc_putu32
	 * or whatever? */
	resbuf->len = klp_total_buf_len(resbuf);
	switch (gc->gc_svc) {
	case RPC_GSS_SVC_NONE:
		break;
	case RPC_GSS_SVC_INTEGRITY:
		stat = klp_svcauth_gss_wrap_resp_integ(rqstp);
		if (stat)
			goto out_err;
		break;
	case RPC_GSS_SVC_PRIVACY:
		stat = klp_svcauth_gss_wrap_resp_priv(rqstp);
		if (stat)
			goto out_err;
		break;
	/*
	 * For any other gc_svc value, svcauth_gss_accept() already set
	 * the auth_error appropriately; just fall through:
	 */
	}

out:
	stat = 0;
out_err:
	if (rqstp->rq_client)
		klp_auth_domain_put(rqstp->rq_client);
	rqstp->rq_client = NULL;
	if (rqstp->rq_gssclient)
		klp_auth_domain_put(rqstp->rq_gssclient);
	rqstp->rq_gssclient = NULL;
	if (rqstp->rq_cred.cr_group_info)
		put_group_info(rqstp->rq_cred.cr_group_info);
	rqstp->rq_cred.cr_group_info = NULL;
	if (gsd->rsci)
		cache_put(&gsd->rsci->h, sn->rsc_cache);
	gsd->rsci = NULL;

	return stat;
}



static int livepatch_bsc1119947_auth_rpcgss_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1119947_auth_rpcgss_module_nb = {
	.notifier_call = livepatch_bsc1119947_auth_rpcgss_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1119947_auth_rpcgss_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(KLP_PATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1119947_auth_rpcgss_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1119947_auth_rpcgss_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1119947_auth_rpcgss_module_nb);
}

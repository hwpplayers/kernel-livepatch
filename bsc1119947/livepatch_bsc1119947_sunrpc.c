/*
 * livepatch_bsc1119947_sunrpc
 *
 * Fix for CVE-2018-16884, bsc#1119947 -- sunrpc.ko part
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
#include <linux/sunrpc/svc.h>
#include <linux/sunrpc/svc_xprt.h>
#include <linux/sunrpc/xprt.h>
#include <linux/sunrpc/stats.h>
#include <linux/sunrpc/debug.h>
#include "livepatch_bsc1119947.h"
#include "kallsyms_relocs.h"

#if !IS_MODULE(CONFIG_SUNRPC)
#error "Live patch supports only CONFIG_SUNRPC=m"
#endif

#if !IS_ENABLED(CONFIG_SUNRPC_DEBUG)
#error "Live patch supports only CONFIG_SUNRPC_DEBUG=y"
#endif

#if !IS_ENABLED(CONFIG_SUNRPC_BACKCHANNEL)
#error "Live patch supports only CONFIG_SUNRPC_BACKCHANNEL=y"
#endif


#define KLP_PATCHED_MODULE "sunrpc"


static unsigned int *klp_rpc_debug;

static int (*klp_svc_authenticate)(struct svc_rqst *rqstp, __be32 *authp);
static int (*klp_svc_authorise)(struct svc_rqst *rqstp);
static void (__printf(2, 3) * klp_svc_printk)(struct svc_rqst *rqstp,
					      const char *fmt, ...);
static void (*klp_xprt_free_bc_request)(struct rpc_rqst *req);
static struct rpc_task *(*klp_rpc_run_bc_task)(struct rpc_rqst *req);
static void (*klp_rpc_put_task)(struct rpc_task *task);

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "rpc_debug", (void *)&klp_rpc_debug, "sunrpc" },
	{ "svc_authenticate", (void *)&klp_svc_authenticate, "sunrpc" },
	{ "svc_authorise", (void *)&klp_svc_authorise, "sunrpc" },
	{ "svc_printk", (void *)&klp_svc_printk, "sunrpc" },
	{ "xprt_free_bc_request", (void *)&klp_xprt_free_bc_request, "sunrpc" },
	{ "rpc_run_bc_task", (void *)&klp_rpc_run_bc_task, "sunrpc" },
	{ "rpc_put_task", (void *)&klp_rpc_put_task, "sunrpc" },
};



/* from include/linux/sunrpc/debug.h */
/* resolve rpc_debug */
#undef ifdebug
# define ifdebug(fac)		if (unlikely((*klp_rpc_debug) & RPCDBG_##fac))


/* from net/sunrpc/svc.c */
#define RPCDBG_FACILITY	RPCDBG_SVCDSP



/*
 * Patched, behaviour is different only if called from also patched
 * klp_bc_svc_process(): act as if rqstp->rq_xprt had been set to
 * NULL.
 */
static int
klp_svc_process_common(struct svc_rqst *rqstp, struct kvec *argv,
		       struct kvec *resv)
{
	struct svc_program	*progp;
	struct svc_version	*versp = NULL;	/* compiler food */
	struct svc_procedure	*procp = NULL;
	struct svc_serv		*serv = rqstp->rq_server;
	kxdrproc_t		xdr;
	__be32			*statp;
	u32			prog, vers, proc;
	__be32			auth_stat, rpc_stat;
	int			auth_res;
	__be32			*reply_statp;

	rpc_stat = rpc_success;

	if (argv->iov_len < 6*4)
		goto err_short_len;

	/* Will be turned off only in gss privacy case: */
	set_bit(RQ_SPLICE_OK, &rqstp->rq_flags);
	/* Will be turned off only when NFSv4 Sessions are used */
	set_bit(RQ_USEDEFERRAL, &rqstp->rq_flags);
	clear_bit(RQ_DROPME, &rqstp->rq_flags);

	/* Setup reply header */
	/*
	 * Fix CVE-2018-16884
	 *  -1 line, +6 lines
	 */
	if (rqstp->rq_prot == IPPROTO_TCP) {
		struct kvec *resv = &rqstp->rq_res.head[0];

		/* tcp needs a space for the record length... */
		svc_putnl(resv, 0);
	}

	svc_putu32(resv, rqstp->rq_xid);

	vers = svc_getnl(argv);

	/* First words of reply: */
	svc_putnl(resv, 1);		/* REPLY */

	if (vers != 2)		/* RPC version number */
		goto err_bad_rpc;

	/* Save position in case we later decide to reject: */
	reply_statp = resv->iov_base + resv->iov_len;

	svc_putnl(resv, 0);		/* ACCEPT */

	rqstp->rq_prog = prog = svc_getnl(argv);	/* program number */
	rqstp->rq_vers = vers = svc_getnl(argv);	/* version number */
	rqstp->rq_proc = proc = svc_getnl(argv);	/* procedure number */

	for (progp = serv->sv_program; progp; progp = progp->pg_next)
		if (prog == progp->pg_prog)
			break;

	/*
	 * Decode auth data, and add verifier to reply buffer.
	 * We do this before anything else in order to get a decent
	 * auth verifier.
	 */
	auth_res = klp_svc_authenticate(rqstp, &auth_stat);
	/* Also give the program a chance to reject this call: */
	if (auth_res == SVC_OK && progp) {
		auth_stat = rpc_autherr_badcred;
		auth_res = progp->pg_authenticate(rqstp);
	}
	switch (auth_res) {
	case SVC_OK:
		break;
	case SVC_GARBAGE:
		goto err_garbage;
	case SVC_SYSERR:
		rpc_stat = rpc_system_err;
		goto err_bad;
	case SVC_DENIED:
		goto err_bad_auth;
	case SVC_CLOSE:
		goto close;
	case SVC_DROP:
		goto dropit;
	case SVC_COMPLETE:
		goto sendit;
	}

	if (progp == NULL)
		goto err_bad_prog;

	if (vers >= progp->pg_nvers ||
	  !(versp = progp->pg_vers[vers]))
		goto err_bad_vers;

	/*
	 * Some protocol versions (namely NFSv4) require some form of
	 * congestion control.  (See RFC 7530 section 3.1 paragraph 2)
	 * In other words, UDP is not allowed. We mark those when setting
	 * up the svc_xprt, and verify that here.
	 *
	 * The spec is not very clear about what error should be returned
	 * when someone tries to access a server that is listening on UDP
	 * for lower versions. RPC_PROG_MISMATCH seems to be the closest
	 * fit.
	 */
	/*
	 * Fix CVE-2018-16884
	 *  -1 line, +1 line
	 */
	if (versp->vs_need_cong_ctrl && NULL &&
	    !test_bit(XPT_CONG_CTRL, &rqstp->rq_xprt->xpt_flags))
		goto err_bad_vers;

	procp = versp->vs_proc + proc;
	if (proc >= versp->vs_nproc || !procp->pc_func)
		goto err_bad_proc;
	rqstp->rq_procinfo = procp;

	/* Syntactic check complete */
	serv->sv_stats->rpccnt++;

	/* Build the reply header. */
	statp = resv->iov_base +resv->iov_len;
	svc_putnl(resv, RPC_SUCCESS);

	/* Bump per-procedure stats counter */
	procp->pc_count++;

	/* Initialize storage for argp and resp */
	memset(rqstp->rq_argp, 0, procp->pc_argsize);
	memset(rqstp->rq_resp, 0, procp->pc_ressize);

	/* un-reserve some of the out-queue now that we have a
	 * better idea of reply size
	 */
	/*
	 * Fix CVE-2018-16884
	 *  -1 line, +1 line
	 *
	 * Explanation: the upstream fix patches svc_reserve() into a
	 * nop for the case that vrqstp->rq_xptr == NULL, i.e. for
	 * vrqstp as setup by bc_svc_process(). The
	 * svc_reserve_auth() invocation below is the only place where
	 * svc_reserve() gets called from bc_svc_process(). So, rather
	 * than live patching svc_reserve(), just mask that call.
	 */
	if (NULL && procp->pc_xdrressize)
		svc_reserve_auth(rqstp, procp->pc_xdrressize<<2);

	/* Call the function that processes the request. */
	if (!versp->vs_dispatch) {
		/* Decode arguments */
		xdr = procp->pc_decode;
		if (xdr && !xdr(rqstp, argv->iov_base, rqstp->rq_argp))
			goto err_garbage;

		*statp = procp->pc_func(rqstp, rqstp->rq_argp, rqstp->rq_resp);

		/* Encode reply */
		if (*statp == rpc_drop_reply ||
		    test_bit(RQ_DROPME, &rqstp->rq_flags)) {
			if (procp->pc_release)
				procp->pc_release(rqstp, NULL, rqstp->rq_resp);
			goto dropit;
		}
		if (*statp == rpc_autherr_badcred) {
			if (procp->pc_release)
				procp->pc_release(rqstp, NULL, rqstp->rq_resp);
			goto err_bad_auth;
		}
		if (*statp == rpc_success &&
		    (xdr = procp->pc_encode) &&
		    !xdr(rqstp, resv->iov_base+resv->iov_len, rqstp->rq_resp)) {
			dprintk("svc: failed to encode reply\n");
			/* serv->sv_stats->rpcsystemerr++; */
			*statp = rpc_system_err;
		}
	} else {
		dprintk("svc: calling dispatcher\n");
		if (!versp->vs_dispatch(rqstp, statp)) {
			/* Release reply info */
			if (procp->pc_release)
				procp->pc_release(rqstp, NULL, rqstp->rq_resp);
			goto dropit;
		}
	}

	/* Check RPC status result */
	if (*statp != rpc_success)
		resv->iov_len = ((void*)statp)  - resv->iov_base + 4;

	/* Release reply info */
	if (procp->pc_release)
		procp->pc_release(rqstp, NULL, rqstp->rq_resp);

	if (procp->pc_encode == NULL)
		goto dropit;

 sendit:
	if (klp_svc_authorise(rqstp))
		goto close;
	return 1;		/* Caller can now send it */

 dropit:
	klp_svc_authorise(rqstp);	/* doesn't hurt to call this twice */
	dprintk("svc: svc_process dropit\n");
	return 0;

 close:
	/*
	 * Fix CVE-2018-16884
	 *  -1 line, +1 line
	 */
	if (NULL && test_bit(XPT_TEMP, &rqstp->rq_xprt->xpt_flags))
		svc_close_xprt(rqstp->rq_xprt);
	dprintk("svc: svc_process close\n");
	return 0;

err_short_len:
	klp_svc_printk(rqstp, "short len %zd, dropping request\n",
			argv->iov_len);

	goto close;

err_bad_rpc:
	serv->sv_stats->rpcbadfmt++;
	svc_putnl(resv, 1);	/* REJECT */
	svc_putnl(resv, 0);	/* RPC_MISMATCH */
	svc_putnl(resv, 2);	/* Only RPCv2 supported */
	svc_putnl(resv, 2);
	goto sendit;

err_bad_auth:
	dprintk("svc: authentication failed (%d)\n", ntohl(auth_stat));
	serv->sv_stats->rpcbadauth++;
	/* Restore write pointer to location of accept status: */
	xdr_ressize_check(rqstp, reply_statp);
	svc_putnl(resv, 1);	/* REJECT */
	svc_putnl(resv, 1);	/* AUTH_ERROR */
	svc_putnl(resv, ntohl(auth_stat));	/* status */
	goto sendit;

err_bad_prog:
	dprintk("svc: unknown program %d\n", prog);
	serv->sv_stats->rpcbadfmt++;
	svc_putnl(resv, RPC_PROG_UNAVAIL);
	goto sendit;

err_bad_vers:
	klp_svc_printk(rqstp, "unknown version (%d for prog %d, %s)\n",
		       vers, prog, progp->pg_name);

	serv->sv_stats->rpcbadfmt++;
	svc_putnl(resv, RPC_PROG_MISMATCH);
	svc_putnl(resv, progp->pg_lovers);
	svc_putnl(resv, progp->pg_hivers);
	goto sendit;

err_bad_proc:
	klp_svc_printk(rqstp, "unknown procedure (%d)\n", proc);

	serv->sv_stats->rpcbadfmt++;
	svc_putnl(resv, RPC_PROC_UNAVAIL);
	goto sendit;

err_garbage:
	klp_svc_printk(rqstp, "failed to decode args\n");

	rpc_stat = rpc_garbage_args;
err_bad:
	serv->sv_stats->rpcbadfmt++;
	svc_putnl(resv, ntohl(rpc_stat));
	goto sendit;
}

/* patched */
int klp_bc_svc_process(struct svc_serv *serv, struct rpc_rqst *req,
		       struct svc_rqst *rqstp)
{
	struct kvec	*argv = &rqstp->rq_arg.head[0];
	struct kvec	*resv = &rqstp->rq_res.head[0];
	struct rpc_task *task;
	int proc_error;
	int error;

	dprintk("svc: %s(%p)\n", __func__, req);

	/* Build the svc_rqst used by the common processing routine */
	rqstp->rq_xprt = serv->sv_bc_xprt;
	rqstp->rq_xid = req->rq_xid;
	rqstp->rq_prot = req->rq_xprt->prot;
	rqstp->rq_server = serv;
	/*
	 * Fix CVE-2018-16884
	 *  +1 line
	 *
	 * Note that the above assignment to rqstp->rq_xprt is left
	 * in place because unpatched third-party modules might call
	 * bc_svc_process() and access that field. Don't break those.
	 */
	klp_shadow_rq_bc_net_set(rqstp, req->rq_xprt->xprt_net);

	rqstp->rq_addrlen = sizeof(req->rq_xprt->addr);
	memcpy(&rqstp->rq_addr, &req->rq_xprt->addr, rqstp->rq_addrlen);
	memcpy(&rqstp->rq_arg, &req->rq_rcv_buf, sizeof(rqstp->rq_arg));
	memcpy(&rqstp->rq_res, &req->rq_snd_buf, sizeof(rqstp->rq_res));

	/* Adjust the argument buffer length */
	rqstp->rq_arg.len = req->rq_private_buf.len;
	if (rqstp->rq_arg.len <= rqstp->rq_arg.head[0].iov_len) {
		rqstp->rq_arg.head[0].iov_len = rqstp->rq_arg.len;
		rqstp->rq_arg.page_len = 0;
	} else if (rqstp->rq_arg.len <= rqstp->rq_arg.head[0].iov_len +
			rqstp->rq_arg.page_len)
		rqstp->rq_arg.page_len = rqstp->rq_arg.len -
			rqstp->rq_arg.head[0].iov_len;
	else
		rqstp->rq_arg.len = rqstp->rq_arg.head[0].iov_len +
			rqstp->rq_arg.page_len;

	/* reset result send buffer "put" position */
	resv->iov_len = 0;

	/*
	 * Skip the next two words because they've already been
	 * processed in the transport
	 */
	svc_getu32(argv);	/* XID */
	svc_getnl(argv);	/* CALLDIR */

	/* Parse and execute the bc call */
	proc_error = klp_svc_process_common(rqstp, argv, resv);

	/*
	 * Fix CVE-2018-16884
	 *  +2 lines
	 */
	klp_shadow_rq_bc_net_destroy(rqstp);

	atomic_inc(&req->rq_xprt->bc_free_slots);
	if (!proc_error) {
		/* Processing error: drop the request */
		klp_xprt_free_bc_request(req);
		return 0;
	}

	/* Finally, send the reply synchronously */
	memcpy(&req->rq_snd_buf, &rqstp->rq_res, sizeof(req->rq_snd_buf));
	task = klp_rpc_run_bc_task(req);
	if (IS_ERR(task)) {
		error = PTR_ERR(task);
		goto out;
	}

	WARN_ON_ONCE(atomic_read(&task->tk_count) != 1);
	error = task->tk_status;
	klp_rpc_put_task(task);

out:
	dprintk("svc: %s(), error=%d\n", __func__, error);
	return error;
}



static int livepatch_bsc1119947_sunrpc_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1119947_sunrpc_module_nb = {
	.notifier_call = livepatch_bsc1119947_sunrpc_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1119947_sunrpc_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(KLP_PATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1119947_sunrpc_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1119947_sunrpc_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1119947_sunrpc_module_nb);
}

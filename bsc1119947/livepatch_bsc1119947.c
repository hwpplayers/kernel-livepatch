/*
 * livepatch_bsc1119947
 *
 * Fix for CVE-2018-16884, bsc#1119947
 *
 *  Upstream commits:
 *  b8be5674fa9a ("sunrpc: use SVC_NET() in svcauth_gss_* functions")
 *  d4b09acf924b ("sunrpc: use-after-free in svc_process_common()")
 *
 *  SLE12(-SP1) commits:
 *  3f13d98021aee924d079e994da959d713588cc1d
 *  cc1b1eb412289fc937541c4bf957d9696711c083
 *
 *  SLE12-SP2 and -SP3 commits:
 *  6f61e427375e9951341927e7c4e9d379e98ed7c1
 *  a9586683776348bca822ad33942d095cd353c1b5
 *
 *  SLE15 commit:
 *  1ac740512f78f5b140fdf408fc4d95384b19d06f
 *  eae94a95abdf35c8a5c5afa1d18d712cb8c1bfac
 *
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
#include <linux/sunrpc/svc_xprt.h>
#include <linux/sunrpc/svc.h>
#include <linux/livepatch.h>
#include "shadow.h"
#include "livepatch_bsc1119947.h"

#define KLP_SHADOW_RQ_BC_NET_ID KLP_SHADOW_ID(1119947, 1)


/* Patched SVC_NET() macro. */
struct net *klp_svc_net(struct svc_rqst *rqstp)
{
	struct net **rq_bc_net = klp_shadow_get(rqstp, KLP_SHADOW_RQ_BC_NET_ID);

	if (rq_bc_net)
		return *rq_bc_net;

	return rqstp->rq_xprt->xpt_net;
}

void klp_shadow_rq_bc_net_set(struct svc_rqst *rqstp, struct net *net)
{
	struct net **rq_bc_net;

	rq_bc_net = klp_shadow_alloc(rqstp, KLP_SHADOW_RQ_BC_NET_ID,
				     sizeof(*rq_bc_net), GFP_KERNEL,
				     NULL, NULL);
	if (!rq_bc_net) {
		/* Don't pass failure to caller. */
		return;
	}

	*rq_bc_net = net;
}

void klp_shadow_rq_bc_net_destroy(struct svc_rqst *rqstp)
{
	klp_shadow_free(rqstp, KLP_SHADOW_RQ_BC_NET_ID, NULL);
}


int livepatch_bsc1119947_init(void)
{
	int ret;

	ret = livepatch_bsc1119947_sunrpc_init();
	if (ret)
		return ret;

	ret = livepatch_bsc1119947_auth_rpcgss_init();
	if (ret) {
		livepatch_bsc1119947_sunrpc_cleanup();
		return ret;
	}

	ret = livepatch_bsc1119947_nfsv4_init();
	if (ret) {
		livepatch_bsc1119947_auth_rpcgss_cleanup();
		livepatch_bsc1119947_sunrpc_cleanup();
		return ret;
	}

	return 0;
}

void livepatch_bsc1119947_cleanup(void)
{
	livepatch_bsc1119947_nfsv4_cleanup();
	livepatch_bsc1119947_auth_rpcgss_cleanup();
	livepatch_bsc1119947_sunrpc_cleanup();
}

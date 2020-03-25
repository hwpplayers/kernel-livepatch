/*
 * livepatch_bsc1165631
 *
 * Fix for CVE-2020-1749, bsc#1165631
 *
 *  Upstream commits:
 *  c4e85f73afb6 ("net: ipv6: add net argument to ip6_dst_lookup_flow")
 *  6c8991f41546 ("net: ipv6_stub: use ip6_dst_lookup_flow instead of
 *                 ip6_dst_lookup")
 *
 *  SLE12-SP1 commit:
 *  none yet
 *
 *  SLE12-SP2 and -SP3 commit:
 *  none yet
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  none yet
 *
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

#include <net/dst.h>
#include <net/flow.h>
#include <uapi/linux/in6.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1165631.h"
#include "../kallsyms_relocs.h"

/* from net/ipv6/ip6_output.c */
static int (*klpe_ip6_dst_lookup_tail)(struct net *net, const struct sock *sk,
				       struct dst_entry **dst,
				       struct flowi6 *fl6);

/*
 * Fix CVE-2020-1749
 *  -1 line, +3 lines
 */
struct dst_entry *klpp_ip6_dst_lookup_flow(struct net *net,
					   const struct sock *sk,
					   struct flowi6 *fl6,
					   const struct in6_addr *final_dst)
{
	struct dst_entry *dst = NULL;
	int err;

	/*
	 * Fix CVE-2020-1749
	 *  -1 line, +1 line
	 */
	err = (*klpe_ip6_dst_lookup_tail)(net, sk, &dst, fl6);
	if (err)
		return ERR_PTR(err);
	if (final_dst)
		fl6->daddr = *final_dst;

	/*
	 * Fix CVE-2020-1749
	 *  -1 line, +1 line
	 */
	return xfrm_lookup_route(net, dst, flowi6_to_flowi(fl6), sk, 0);
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "ip6_dst_lookup_tail", (void *)&klpe_ip6_dst_lookup_tail },
};

int livepatch_bsc1165631_init(void)
{
	int r;

	r =  __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));

	if (r)
		return r;

	r = livepatch_bsc1165631_vxlan_init();
	if (r)
		return r;

	r = livepatch_bsc1165631_geneve_init();
	if (r) {
		livepatch_bsc1165631_vxlan_cleanup();
		return r;
	}

	r = livepatch_bsc1165631_tipc_init();
	if (r) {
		livepatch_bsc1165631_geneve_cleanup();
		livepatch_bsc1165631_vxlan_cleanup();
		return r;
	}

	r = livepatch_bsc1165631_rdma_rxe_init();
	if (r) {
		livepatch_bsc1165631_tipc_cleanup();
		livepatch_bsc1165631_geneve_cleanup();
		livepatch_bsc1165631_vxlan_cleanup();
		return r;
	}

	return 0;
}

void livepatch_bsc1165631_cleanup(void)
{
	livepatch_bsc1165631_rdma_rxe_cleanup();
	livepatch_bsc1165631_tipc_cleanup();
	livepatch_bsc1165631_geneve_cleanup();
	livepatch_bsc1165631_vxlan_cleanup();
}

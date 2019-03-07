/*
 * livepatch_bsc1126284
 *
 * Fix for CVE-2019-8912, bsc#1126284
 *
 *  Upstream commit:
 *  9060cb719e61 ("net: crypto set sk to NULL when af_alg_release.")
 *
 *  SLE12(-SP1) commit:
 *  not affected
 *
 *  SLE12-SP2 commit:
 *  not affected
 *
 *  SLE12-SP3 commit:
 *  not affected
 *
 *  SLE12-SP4 commit:
 *  9863801ecea339cdc5196b28f4f69a866265b3da
 *
 *  SLE15 commit:
 *  9863801ecea339cdc5196b28f4f69a866265b3da
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
#include <linux/net.h>
#include <net/sock.h>
#include "livepatch_bsc1126284.h"

#if !IS_MODULE(CONFIG_CRYPTO_USER_API)
#error "Live patch supports only CONFIG_CRYPTO_USER_API=m"
#endif


/* patched */
int klp_af_alg_release(struct socket *sock)
{
	/*
	 * Fix CVE-2019-8912
	 *  -2 lines, +4 lines
	 */
	if (sock->sk) {
		sock_put(sock->sk);
		sock->sk = NULL;
	}
	return 0;
}

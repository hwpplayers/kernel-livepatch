/*
 * livepatch_bsc1165631_geneve
 *
 * Fix for CVE-2020-1749, bsc#1165631 (geneve.ko part)
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

#if !IS_MODULE(CONFIG_GENEVE)
#error "Live patch supports only CONFIG_GENEVE=m"
#endif

#define LIVEPATCHED_MODULE "geneve"

#define pr_fmt(fmt) LIVEPATCHED_MODULE ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/hash.h>
#include <net/dst_metadata.h>
#include <net/gro_cells.h>
#include <net/rtnetlink.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1165631.h"
#include "../kallsyms_relocs.h"

/* from drivers/net/geneve.c */
#define VNI_HASH_BITS		10
#define VNI_HASH_SIZE		(1<<VNI_HASH_BITS)

struct geneve_dev_node {
	struct hlist_node hlist;
	struct geneve_dev *geneve;
};

struct geneve_dev {
	struct geneve_dev_node hlist4;	/* vni hash table for IPv4 socket */
#if IS_ENABLED(CONFIG_IPV6)
	struct geneve_dev_node hlist6;	/* vni hash table for IPv6 socket */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct net	   *net;	/* netns for packet i/o */
	struct net_device  *dev;	/* netdev for geneve tunnel */
	struct ip_tunnel_info info;
	struct geneve_sock __rcu *sock4;	/* IPv4 socket used for geneve tunnel */
#if IS_ENABLED(CONFIG_IPV6)
	struct geneve_sock __rcu *sock6;	/* IPv6 socket used for geneve tunnel */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct list_head   next;	/* geneve's per namespace list */
	struct gro_cells   gro_cells;
	bool		   collect_md;
	bool		   use_udp6_rx_checksums;
};

struct geneve_sock {
	bool			collect_md;
	struct list_head	list;
	struct socket		*sock;
	struct rcu_head		rcu;
	int			refcnt;
	struct hlist_head	vni_list[VNI_HASH_SIZE];
};

#if IS_ENABLED(CONFIG_IPV6)
struct dst_entry *klpp_geneve_get_v6_dst(struct sk_buff *skb,
					   struct net_device *dev,
					   struct flowi6 *fl6,
					   const struct ip_tunnel_info *info)
{
	bool use_cache = ip_tunnel_dst_cache_usable(skb, info);
	struct geneve_dev *geneve = netdev_priv(dev);
	struct dst_entry *dst = NULL;
	struct dst_cache *dst_cache;
	struct geneve_sock *gs6;
	__u8 prio;

	gs6 = rcu_dereference(geneve->sock6);
	if (!gs6)
		return ERR_PTR(-EIO);

	memset(fl6, 0, sizeof(*fl6));
	fl6->flowi6_mark = skb->mark;
	fl6->flowi6_proto = IPPROTO_UDP;
	fl6->daddr = info->key.u.ipv6.dst;
	fl6->saddr = info->key.u.ipv6.src;
	prio = info->key.tos;
	if ((prio == 1) && !geneve->collect_md) {
		prio = ip_tunnel_get_dsfield(ip_hdr(skb), skb);
		use_cache = false;
	}

	fl6->flowlabel = ip6_make_flowinfo(RT_TOS(prio),
					   info->key.label);
	dst_cache = (struct dst_cache *)&info->dst_cache;
	if (use_cache) {
		dst = dst_cache_get_ip6(dst_cache, &fl6->saddr);
		if (dst)
			return dst;
	}

	/*
	 * Fix CVE-2020-1749
	 *  -1 line, +3 lines
	 */
	dst = klpp_ip6_dst_lookup_flow(geneve->net, gs6->sock->sk, fl6,
				       NULL);
	if (IS_ERR(dst)) {
		netdev_dbg(dev, "no route to %pI6\n", &fl6->daddr);
		return ERR_PTR(-ENETUNREACH);
	}
	if (dst->dev == dev) { /* is this necessary? */
		netdev_dbg(dev, "circular route to %pI6\n", &fl6->daddr);
		dst_release(dst);
		return ERR_PTR(-ELOOP);
	}

	if (use_cache)
		dst_cache_set_ip6(dst_cache, dst, &fl6->saddr);
	return dst;
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

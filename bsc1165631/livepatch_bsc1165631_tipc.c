/*
 * livepatch_bsc1165631_tipc
 *
 * Fix for CVE-2020-1749, bsc#1165631 (tipc.ko part)
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

#if !IS_MODULE(CONFIG_TIPC)
#error "Live patch supports only CONFIG_TIPC=m"
#endif

#if !IS_ENABLED(CONFIG_TIPC_MEDIA_UDP)
#error "Live patch supports only CONFIG_TIPC_MEDIA_UDP=y"
#endif

#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/udp_tunnel.h>
#include <net/addrconf.h>
#include <uapi/linux/tipc.h>
#include <linux/tipc_netlink.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/atomic.h>
#include <asm/hardirq.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/rtnetlink.h>
#include <linux/etherdevice.h>
#include <linux/rhashtable.h>
#include <net/netns/generic.h>
#include <net/netlink.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1165631.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "tipc"


/* from include/net/udp_tunnel.h */
static void (*klpe_udp_tunnel_xmit_skb)(struct rtable *rt, struct sock *sk, struct sk_buff *skb,
			 __be32 src, __be32 dst, __u8 tos, __u8 ttl,
			 __be16 df, __be16 src_port, __be16 dst_port,
			 bool xnet, bool nocheck);

#if IS_ENABLED(CONFIG_IPV6)
static int (*klpe_udp_tunnel6_xmit_skb)(struct dst_entry *dst, struct sock *sk,
			 struct sk_buff *skb,
			 struct net_device *dev, struct in6_addr *saddr,
			 struct in6_addr *daddr,
			 __u8 prio, __u8 ttl, __be32 label,
			 __be16 src_port, __be16 dst_port, bool nocheck);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif


/* from net/tipc/bearer.h */
#define TIPC_MEDIA_INFO_SIZE	32

#define TIPC_REPLICAST_SUPPORT  2

struct tipc_media_addr {
	u8 value[TIPC_MEDIA_INFO_SIZE];
	u8 media_id;
	u8 broadcast;
};

struct tipc_bearer {
	void __rcu *media_ptr;			/* initalized by media */
	u32 mtu;				/* initalized by media */
	struct tipc_media_addr addr;		/* initalized by media */
	char name[TIPC_MAX_BEARER_NAME];
	struct tipc_media *media;
	struct tipc_media_addr bcast_addr;
	struct rcu_head rcu;
	u32 priority;
	u32 window;
	u32 tolerance;
	u32 domain;
	u32 identity;
	struct tipc_link_req *link_req;
	char net_plane;
	unsigned long up;
};


/* from net/tipc/udp_media.c */
#define UDP_MIN_HEADROOM        48

struct udp_media_addr {
	__be16	proto;
	__be16	port;
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	};
};

struct udp_replicast {
	struct udp_media_addr addr;
	struct rcu_head rcu;
	struct list_head list;
};

struct udp_bearer {
	struct tipc_bearer __rcu *bearer;
	struct socket *ubsock;
	u32 ifindex;
	struct work_struct work;
	struct udp_replicast rcast;
};

static int klpp_tipc_udp_xmit(struct net *net, struct sk_buff *skb,
			 struct udp_bearer *ub, struct udp_media_addr *src,
			 struct udp_media_addr *dst)
{
	int ttl, err = 0;
	struct rtable *rt;

	if (dst->proto == htons(ETH_P_IP)) {
		struct flowi4 fl = {
			.daddr = dst->ipv4.s_addr,
			.saddr = src->ipv4.s_addr,
			.flowi4_mark = skb->mark,
			.flowi4_proto = IPPROTO_UDP
		};
		rt = ip_route_output_key(net, &fl);
		if (IS_ERR(rt)) {
			err = PTR_ERR(rt);
			goto tx_error;
		}

		ttl = ip4_dst_hoplimit(&rt->dst);
		(*klpe_udp_tunnel_xmit_skb)(rt, ub->ubsock->sk, skb, src->ipv4.s_addr,
				    dst->ipv4.s_addr, 0, ttl, 0, src->port,
				    dst->port, false, true);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		struct dst_entry *ndst;
		struct flowi6 fl6 = {
			.flowi6_oif = ub->ifindex,
			.daddr = dst->ipv6,
			.saddr = src->ipv6,
			.flowi6_proto = IPPROTO_UDP
		};
		/*
		 * Fix CVE-2020-1749
		 *  -4 lines, +7 lines
		 */
		ndst = klpp_ip6_dst_lookup_flow(net,
						ub->ubsock->sk,
						&fl6, NULL);
		if (IS_ERR(ndst)) {
			err = PTR_ERR(ndst);
			goto tx_error;
		}
		ttl = ip6_dst_hoplimit(ndst);
		err = (*klpe_udp_tunnel6_xmit_skb)(ndst, ub->ubsock->sk, skb, NULL,
					   &src->ipv6, &dst->ipv6, 0, ttl, 0,
					   src->port, dst->port, false);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	}
	return err;

tx_error:
	kfree_skb(skb);
	return err;
}

int klpp_tipc_udp_send_msg(struct net *net, struct sk_buff *skb,
			     struct tipc_bearer *b,
			     struct tipc_media_addr *addr)
{
	struct udp_media_addr *src = (struct udp_media_addr *)&b->addr.value;
	struct udp_media_addr *dst = (struct udp_media_addr *)&addr->value;
	struct udp_replicast *rcast;
	struct udp_bearer *ub;
	int err = 0;

	if (skb_headroom(skb) < UDP_MIN_HEADROOM) {
		err = pskb_expand_head(skb, UDP_MIN_HEADROOM, 0, GFP_ATOMIC);
		if (err)
			goto out;
	}

	skb_set_inner_protocol(skb, htons(ETH_P_TIPC));
	ub = rcu_dereference_rtnl(b->media_ptr);
	if (!ub) {
		err = -ENODEV;
		goto out;
	}

	if (addr->broadcast != TIPC_REPLICAST_SUPPORT)
		return klpp_tipc_udp_xmit(net, skb, ub, src, dst);

	/* Replicast, send an skb to each configured IP address */
	list_for_each_entry_rcu(rcast, &ub->rcast.list, list) {
		struct sk_buff *_skb;

		_skb = pskb_copy(skb, GFP_ATOMIC);
		if (!_skb) {
			err = -ENOMEM;
			goto out;
		}

		err = klpp_tipc_udp_xmit(net, _skb, ub, src, &rcast->addr);
		if (err)
			goto out;
	}
	err = 0;
out:
	kfree_skb(skb);
	return err;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "udp_tunnel6_xmit_skb", (void *)&klpe_udp_tunnel6_xmit_skb,
	  "ip6_udp_tunnel" },
	{ "udp_tunnel_xmit_skb", (void *)&klpe_udp_tunnel_xmit_skb,
	  "udp_tunnel" },
};

static int livepatch_bsc1165631_tipc_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1165631_tipc_module_nb = {
	.notifier_call = livepatch_bsc1165631_tipc_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1165631_tipc_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1165631_tipc_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1165631_tipc_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1165631_tipc_module_nb);
}

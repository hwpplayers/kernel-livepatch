/*
 * livepatch_bsc1165631_vxlan
 *
 * Fix for CVE-2020-1749, bsc#1165631 (vxlan.ko part)
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

#if !IS_MODULE(CONFIG_VXLAN)
#error "Live patch supports only CONFIG_VXLAN=m"
#endif

#define LIVEPATCHED_MODULE "vxlan"

#define pr_fmt(fmt) LIVEPATCHED_MODULE ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ethtool.h>
#include <net/ndisc.h>
#include <net/ip.h>
#include <net/rtnetlink.h>
#include <net/inet_ecn.h>
#include <net/net_namespace.h>
#include <net/vxlan.h>

#include "livepatch_bsc1165631.h"
#include "../kallsyms_relocs.h"


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


/* from drivers/net/vxlan.c */
static inline struct hlist_head *vni_head(struct vxlan_sock *vs, __be32 vni)
{
	return &vs->vni_list[hash_32((__force u32)vni, VNI_HASH_BITS)];
}

static struct vxlan_sock *(*klpe_vxlan_find_sock)(struct net *net, sa_family_t family,
					  __be16 port, u32 flags);

static struct vxlan_dev *vxlan_vs_find_vni(struct vxlan_sock *vs, __be32 vni)
{
	struct vxlan_dev_node *node;

	/* For flow based devices, map all packets to VNI 0 */
	if (vs->flags & VXLAN_F_COLLECT_METADATA)
		vni = 0;

	hlist_for_each_entry_rcu(node, vni_head(vs, vni), hlist) {
		if (node->vxlan->default_dst.remote_vni == vni)
			return node->vxlan;
	}

	return NULL;
}

static struct vxlan_dev *klpr_vxlan_find_vni(struct net *net, __be32 vni,
					sa_family_t family, __be16 port,
					u32 flags)
{
	struct vxlan_sock *vs;

	vs = (*klpe_vxlan_find_sock)(net, family, port, flags);
	if (!vs)
		return NULL;

	return vxlan_vs_find_vni(vs, vni);
}

static bool (*klpe_vxlan_snoop)(struct net_device *dev,
			union vxlan_addr *src_ip, const u8 *src_mac,
			__be32 vni);

static void vxlan_build_gbp_hdr(struct vxlanhdr *vxh, u32 vxflags,
				struct vxlan_metadata *md)
{
	struct vxlanhdr_gbp *gbp;

	if (!md->gbp)
		return;

	gbp = (struct vxlanhdr_gbp *)vxh;
	vxh->vx_flags |= VXLAN_HF_GBP;

	if (md->gbp & VXLAN_GBP_DONT_LEARN)
		gbp->dont_learn = 1;

	if (md->gbp & VXLAN_GBP_POLICY_APPLIED)
		gbp->policy_applied = 1;

	gbp->policy_id = htons(md->gbp & VXLAN_GBP_ID_MASK);
}

static int vxlan_build_gpe_hdr(struct vxlanhdr *vxh, u32 vxflags,
			       __be16 protocol)
{
	struct vxlanhdr_gpe *gpe = (struct vxlanhdr_gpe *)vxh;

	gpe->np_applied = 1;

	switch (protocol) {
	case htons(ETH_P_IP):
		gpe->next_protocol = VXLAN_GPE_NP_IPV4;
		return 0;
	case htons(ETH_P_IPV6):
		gpe->next_protocol = VXLAN_GPE_NP_IPV6;
		return 0;
	case htons(ETH_P_TEB):
		gpe->next_protocol = VXLAN_GPE_NP_ETHERNET;
		return 0;
	}
	return -EPFNOSUPPORT;
}

static int vxlan_build_skb(struct sk_buff *skb, struct dst_entry *dst,
			   int iphdr_len, __be32 vni,
			   struct vxlan_metadata *md, u32 vxflags,
			   bool udp_sum)
{
	struct vxlanhdr *vxh;
	int min_headroom;
	int err;
	int type = udp_sum ? SKB_GSO_UDP_TUNNEL_CSUM : SKB_GSO_UDP_TUNNEL;
	__be16 inner_protocol = htons(ETH_P_TEB);

	if ((vxflags & VXLAN_F_REMCSUM_TX) &&
	    skb->ip_summed == CHECKSUM_PARTIAL) {
		int csum_start = skb_checksum_start_offset(skb);

		if (csum_start <= VXLAN_MAX_REMCSUM_START &&
		    !(csum_start & VXLAN_RCO_SHIFT_MASK) &&
		    (skb->csum_offset == offsetof(struct udphdr, check) ||
		     skb->csum_offset == offsetof(struct tcphdr, check)))
			type |= SKB_GSO_TUNNEL_REMCSUM;
	}

	min_headroom = LL_RESERVED_SPACE(dst->dev) + dst->header_len
			+ VXLAN_HLEN + iphdr_len;

	/* Need space for new headers (invalidates iph ptr) */
	err = skb_cow_head(skb, min_headroom);
	if (unlikely(err))
		return err;

	err = iptunnel_handle_offloads(skb, type);
	if (err)
		return err;

	vxh = __skb_push(skb, sizeof(*vxh));
	vxh->vx_flags = VXLAN_HF_VNI;
	vxh->vx_vni = vxlan_vni_field(vni);

	if (type & SKB_GSO_TUNNEL_REMCSUM) {
		unsigned int start;

		start = skb_checksum_start_offset(skb) - sizeof(struct vxlanhdr);
		vxh->vx_vni |= vxlan_compute_rco(start, skb->csum_offset);
		vxh->vx_flags |= VXLAN_HF_RCO;

		if (!skb_is_gso(skb)) {
			skb->ip_summed = CHECKSUM_NONE;
			skb->encapsulation = 0;
		}
	}

	if (vxflags & VXLAN_F_GBP)
		vxlan_build_gbp_hdr(vxh, vxflags, md);
	if (vxflags & VXLAN_F_GPE) {
		err = vxlan_build_gpe_hdr(vxh, vxflags, skb->protocol);
		if (err < 0)
			return err;
		inner_protocol = skb->protocol;
	}

	skb_set_inner_protocol(skb, inner_protocol);
	return 0;
}

static struct rtable *vxlan_get_route(struct vxlan_dev *vxlan, struct net_device *dev,
				      struct vxlan_sock *sock4,
				      struct sk_buff *skb, int oif, u8 tos,
				      __be32 daddr, __be32 *saddr, __be16 dport, __be16 sport,
				      struct dst_cache *dst_cache,
				      const struct ip_tunnel_info *info)
{
	bool use_cache = ip_tunnel_dst_cache_usable(skb, info);
	struct rtable *rt = NULL;
	struct flowi4 fl4;

	if (!sock4)
		return ERR_PTR(-EIO);

	if (tos && !info)
		use_cache = false;
	if (use_cache) {
		rt = dst_cache_get_ip4(dst_cache, saddr);
		if (rt)
			return rt;
	}

	memset(&fl4, 0, sizeof(fl4));
	fl4.flowi4_oif = oif;
	fl4.flowi4_tos = RT_TOS(tos);
	fl4.flowi4_mark = skb->mark;
	fl4.flowi4_proto = IPPROTO_UDP;
	fl4.daddr = daddr;
	fl4.saddr = *saddr;
	fl4.fl4_dport = dport;
	fl4.fl4_sport = sport;

	rt = ip_route_output_key(vxlan->net, &fl4);
	if (likely(!IS_ERR(rt))) {
		if (rt->dst.dev == dev) {
			netdev_dbg(dev, "circular route to %pI4\n", &daddr);
			ip_rt_put(rt);
			return ERR_PTR(-ELOOP);
		}

		*saddr = fl4.saddr;
		if (use_cache)
			dst_cache_set_ip4(dst_cache, &rt->dst, fl4.saddr);
	} else {
		netdev_dbg(dev, "no route to %pI4\n", &daddr);
		return ERR_PTR(-ENETUNREACH);
	}
	return rt;
}

#if IS_ENABLED(CONFIG_IPV6)
static struct dst_entry *klpp_vxlan6_get_route(struct vxlan_dev *vxlan,
					  struct net_device *dev,
					  struct vxlan_sock *sock6,
					  struct sk_buff *skb, int oif, u8 tos,
					  __be32 label,
					  const struct in6_addr *daddr,
					  struct in6_addr *saddr,
					  __be16 dport, __be16 sport,
					  struct dst_cache *dst_cache,
					  const struct ip_tunnel_info *info)
{
	bool use_cache = ip_tunnel_dst_cache_usable(skb, info);
	struct dst_entry *ndst;
	struct flowi6 fl6;
	/*
	 * Fix CVE-2020-1749
	 *  -1 line
	 */

	if (!sock6)
		return ERR_PTR(-EIO);

	if (tos && !info)
		use_cache = false;
	if (use_cache) {
		ndst = dst_cache_get_ip6(dst_cache, saddr);
		if (ndst)
			return ndst;
	}

	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_oif = oif;
	fl6.daddr = *daddr;
	fl6.saddr = *saddr;
	fl6.flowlabel = ip6_make_flowinfo(RT_TOS(tos), label);
	fl6.flowi6_mark = skb->mark;
	fl6.flowi6_proto = IPPROTO_UDP;
	fl6.fl6_dport = dport;
	fl6.fl6_sport = sport;

	/*
	 * Fix CVE-2020-1749
	 *  -4 lines, +3 lines
	 */
	ndst = klpp_ip6_dst_lookup_flow(vxlan->net, sock6->sock->sk,
					&fl6, NULL);
	if (unlikely(IS_ERR(ndst))) {
		netdev_dbg(dev, "no route to %pI6\n", daddr);
		return ERR_PTR(-ENETUNREACH);
	}

	if (unlikely(ndst->dev == dev)) {
		netdev_dbg(dev, "circular route to %pI6\n", daddr);
		dst_release(ndst);
		return ERR_PTR(-ELOOP);
	}

	*saddr = fl6.saddr;
	if (use_cache)
		dst_cache_set_ip6(dst_cache, ndst, saddr);
	return ndst;
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

static void klpr_vxlan_encap_bypass(struct sk_buff *skb, struct vxlan_dev *src_vxlan,
			       struct vxlan_dev *dst_vxlan, __be32 vni)
{
	struct pcpu_sw_netstats *tx_stats, *rx_stats;
	union vxlan_addr loopback;
	union vxlan_addr *remote_ip = &dst_vxlan->default_dst.remote_ip;
	struct net_device *dev;
	int len = skb->len;

	tx_stats = this_cpu_ptr(src_vxlan->dev->tstats);
	rx_stats = this_cpu_ptr(dst_vxlan->dev->tstats);
	skb->pkt_type = PACKET_HOST;
	skb->encapsulation = 0;
	skb->dev = dst_vxlan->dev;
	__skb_pull(skb, skb_network_offset(skb));

	if (remote_ip->sa.sa_family == AF_INET) {
		loopback.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		loopback.sa.sa_family =  AF_INET;
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		loopback.sin6.sin6_addr = in6addr_loopback;
		loopback.sa.sa_family =  AF_INET6;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	}

	rcu_read_lock();
	dev = skb->dev;
	if (unlikely(!(dev->flags & IFF_UP))) {
		kfree_skb(skb);
		goto drop;
	}

	if (dst_vxlan->flags & VXLAN_F_LEARN)
		(*klpe_vxlan_snoop)(dev, &loopback, eth_hdr(skb)->h_source, vni);

	u64_stats_update_begin(&tx_stats->syncp);
	tx_stats->tx_packets++;
	tx_stats->tx_bytes += len;
	u64_stats_update_end(&tx_stats->syncp);

	if (netif_rx(skb) == NET_RX_SUCCESS) {
		u64_stats_update_begin(&rx_stats->syncp);
		rx_stats->rx_packets++;
		rx_stats->rx_bytes += len;
		u64_stats_update_end(&rx_stats->syncp);
	} else {
drop:
		dev->stats.rx_dropped++;
	}
	rcu_read_unlock();
}

static int klpr_encap_bypass_if_local(struct sk_buff *skb, struct net_device *dev,
				 struct vxlan_dev *vxlan, union vxlan_addr *daddr,
				 __be16 dst_port, __be32 vni, struct dst_entry *dst,
				 u32 rt_flags)
{
#if IS_ENABLED(CONFIG_IPV6)
	BUILD_BUG_ON(RTCF_LOCAL != RTF_LOCAL);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	if (rt_flags & RTCF_LOCAL &&
	    !(rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))) {
		struct vxlan_dev *dst_vxlan;

		dst_release(dst);
		dst_vxlan = klpr_vxlan_find_vni(vxlan->net, vni,
					   daddr->sa.sa_family, dst_port,
					   vxlan->flags);
		if (!dst_vxlan) {
			dev->stats.tx_errors++;
			kfree_skb(skb);

			return -ENOENT;
		}
		klpr_vxlan_encap_bypass(skb, vxlan, dst_vxlan, vni);
		return 1;
	}

	return 0;
}

void klpp_vxlan_xmit_one(struct sk_buff *skb, struct net_device *dev,
			   __be32 default_vni, struct vxlan_rdst *rdst,
			   bool did_rsc)
{
	struct dst_cache *dst_cache;
	struct ip_tunnel_info *info;
	struct vxlan_dev *vxlan = netdev_priv(dev);
	const struct iphdr *old_iph = ip_hdr(skb);
	union vxlan_addr *dst;
	union vxlan_addr remote_ip, local_ip;
	struct vxlan_metadata _md;
	struct vxlan_metadata *md = &_md;
	__be16 src_port = 0, dst_port;
	struct dst_entry *ndst = NULL;
	__be32 vni, label;
	__u8 tos, ttl;
	int err;
	u32 flags = vxlan->flags;
	bool udp_sum = false;
	bool xnet = !net_eq(vxlan->net, dev_net(vxlan->dev));

	info = skb_tunnel_info(skb);

	if (rdst) {
		dst = &rdst->remote_ip;
		if (vxlan_addr_any(dst)) {
			if (did_rsc) {
				/* short-circuited back to local bridge */
				klpr_vxlan_encap_bypass(skb, vxlan, vxlan, default_vni);
				return;
			}
			goto drop;
		}

		dst_port = rdst->remote_port ? rdst->remote_port : vxlan->cfg.dst_port;
		vni = (rdst->remote_vni) ? : default_vni;
		local_ip = vxlan->cfg.saddr;
		dst_cache = &rdst->dst_cache;
		md->gbp = skb->mark;
		if (flags & VXLAN_F_TTL_INHERIT) {
			ttl = ip_tunnel_get_ttl(old_iph, skb);
		} else {
			ttl = vxlan->cfg.ttl;
			if (!ttl && vxlan_addr_multicast(dst))
				ttl = 1;
		}

		tos = vxlan->cfg.tos;
		if (tos == 1)
			tos = ip_tunnel_get_dsfield(old_iph, skb);

		if (dst->sa.sa_family == AF_INET)
			udp_sum = !(flags & VXLAN_F_UDP_ZERO_CSUM_TX);
		else
			udp_sum = !(flags & VXLAN_F_UDP_ZERO_CSUM6_TX);
		label = vxlan->cfg.label;
	} else {
		if (!info) {
			WARN_ONCE(1, "%s: Missing encapsulation instructions\n",
				  dev->name);
			goto drop;
		}
		remote_ip.sa.sa_family = ip_tunnel_info_af(info);
		if (remote_ip.sa.sa_family == AF_INET) {
			remote_ip.sin.sin_addr.s_addr = info->key.u.ipv4.dst;
			local_ip.sin.sin_addr.s_addr = info->key.u.ipv4.src;
		} else {
			remote_ip.sin6.sin6_addr = info->key.u.ipv6.dst;
			local_ip.sin6.sin6_addr = info->key.u.ipv6.src;
		}
		dst = &remote_ip;
		dst_port = info->key.tp_dst ? : vxlan->cfg.dst_port;
		vni = tunnel_id_to_key32(info->key.tun_id);
		dst_cache = &info->dst_cache;
		if (info->options_len)
			md = ip_tunnel_info_opts(info);
		ttl = info->key.ttl;
		tos = info->key.tos;
		label = info->key.label;
		udp_sum = !!(info->key.tun_flags & TUNNEL_CSUM);
	}
	src_port = udp_flow_src_port(dev_net(dev), skb, vxlan->cfg.port_min,
				     vxlan->cfg.port_max, true);

	rcu_read_lock();
	if (dst->sa.sa_family == AF_INET) {
		struct vxlan_sock *sock4 = rcu_dereference(vxlan->vn4_sock);
		struct rtable *rt;
		__be16 df = 0;

		rt = vxlan_get_route(vxlan, dev, sock4, skb,
				     rdst ? rdst->remote_ifindex : 0, tos,
				     dst->sin.sin_addr.s_addr,
				     &local_ip.sin.sin_addr.s_addr,
				     dst_port, src_port,
				     dst_cache, info);
		if (IS_ERR(rt)) {
			err = PTR_ERR(rt);
			goto tx_error;
		}

		/* Bypass encapsulation if the destination is local */
		if (!info) {
			err = klpr_encap_bypass_if_local(skb, dev, vxlan, dst,
						    dst_port, vni, &rt->dst,
						    rt->rt_flags);
			if (err)
				goto out_unlock;
		} else if (info->key.tun_flags & TUNNEL_DONT_FRAGMENT) {
			df = htons(IP_DF);
		}

		ndst = &rt->dst;
		skb_tunnel_check_pmtu(skb, ndst, VXLAN_HEADROOM);

		tos = ip_tunnel_ecn_encap(RT_TOS(tos), old_iph, skb);
		ttl = ttl ? : ip4_dst_hoplimit(&rt->dst);
		err = vxlan_build_skb(skb, ndst, sizeof(struct iphdr),
				      vni, md, flags, udp_sum);
		if (err < 0)
			goto tx_error;

		(*klpe_udp_tunnel_xmit_skb)(rt, sock4->sock->sk, skb, local_ip.sin.sin_addr.s_addr,
				    dst->sin.sin_addr.s_addr, tos, ttl, df,
				    src_port, dst_port, xnet, !udp_sum);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		struct vxlan_sock *sock6 = rcu_dereference(vxlan->vn6_sock);

		ndst = klpp_vxlan6_get_route(vxlan, dev, sock6, skb,
					rdst ? rdst->remote_ifindex : 0, tos,
					label, &dst->sin6.sin6_addr,
					&local_ip.sin6.sin6_addr,
					dst_port, src_port,
					dst_cache, info);
		if (IS_ERR(ndst)) {
			err = PTR_ERR(ndst);
			ndst = NULL;
			goto tx_error;
		}

		if (!info) {
			u32 rt6i_flags = ((struct rt6_info *)ndst)->rt6i_flags;

			err = klpr_encap_bypass_if_local(skb, dev, vxlan, dst,
						    dst_port, vni, ndst,
						    rt6i_flags);
			if (err)
				goto out_unlock;
		}

		skb_tunnel_check_pmtu(skb, ndst, VXLAN6_HEADROOM);

		tos = ip_tunnel_ecn_encap(RT_TOS(tos), old_iph, skb);
		ttl = ttl ? : ip6_dst_hoplimit(ndst);
		skb_scrub_packet(skb, xnet);
		err = vxlan_build_skb(skb, ndst, sizeof(struct ipv6hdr),
				      vni, md, flags, udp_sum);
		if (err < 0)
			goto tx_error;

		(*klpe_udp_tunnel6_xmit_skb)(ndst, sock6->sock->sk, skb, dev,
				     &local_ip.sin6.sin6_addr,
				     &dst->sin6.sin6_addr, tos, ttl,
				     label, src_port, dst_port, !udp_sum);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	}
out_unlock:
	rcu_read_unlock();
	return;

drop:
	dev->stats.tx_dropped++;
	dev_kfree_skb(skb);
	return;

tx_error:
	rcu_read_unlock();
	if (err == -ELOOP)
		dev->stats.collisions++;
	else if (err == -ENETUNREACH)
		dev->stats.tx_carrier_errors++;
	dst_release(ndst);
	dev->stats.tx_errors++;
	kfree_skb(skb);
}

int klpp_vxlan_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct ip_tunnel_info *info = skb_tunnel_info(skb);
	__be16 sport, dport;

	sport = udp_flow_src_port(dev_net(dev), skb, vxlan->cfg.port_min,
				  vxlan->cfg.port_max, true);
	dport = info->key.tp_dst ? : vxlan->cfg.dst_port;

	if (ip_tunnel_info_af(info) == AF_INET) {
		struct vxlan_sock *sock4 = rcu_dereference(vxlan->vn4_sock);
		struct rtable *rt;

		rt = vxlan_get_route(vxlan, dev, sock4, skb, 0, info->key.tos,
				     info->key.u.ipv4.dst,
				     &info->key.u.ipv4.src, dport, sport,
				     &info->dst_cache, info);
		if (IS_ERR(rt))
			return PTR_ERR(rt);
		ip_rt_put(rt);
	} else {
#if IS_ENABLED(CONFIG_IPV6)
		struct vxlan_sock *sock6 = rcu_dereference(vxlan->vn6_sock);
		struct dst_entry *ndst;

		ndst = klpp_vxlan6_get_route(vxlan, dev, sock6, skb, 0, info->key.tos,
					info->key.label, &info->key.u.ipv6.dst,
					&info->key.u.ipv6.src, dport, sport,
					&info->dst_cache, info);
		if (IS_ERR(ndst))
			return PTR_ERR(ndst);
		dst_release(ndst);
#else /* !CONFIG_IPV6 */
#error "klp-ccp: non-taken branch"
#endif
	}
	info->key.tp_src = sport;
	info->key.tp_dst = dport;
	return 0;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "udp_tunnel6_xmit_skb", (void *)&klpe_udp_tunnel6_xmit_skb, "ip6_udp_tunnel" },
	{ "udp_tunnel_xmit_skb", (void *)&klpe_udp_tunnel_xmit_skb, "udp_tunnel" },
	{ "vxlan_find_sock", (void *)&klpe_vxlan_find_sock, "vxlan" },
	{ "vxlan_snoop", (void *)&klpe_vxlan_snoop, "vxlan" }
};

static int livepatch_bsc1165631_vxlan_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1165631_vxlan_module_nb = {
	.notifier_call = livepatch_bsc1165631_vxlan_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1165631_vxlan_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1165631_vxlan_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1165631_vxlan_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1165631_vxlan_module_nb);
}

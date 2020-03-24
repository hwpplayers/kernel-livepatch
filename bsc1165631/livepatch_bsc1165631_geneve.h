#ifndef _LIVEPATCH_BSC1165631_GENEVE_H
#define _LIVEPATCH_BSC1165631_GENEVE_H

static inline int livepatch_bsc1165631_geneve_init(void) { return 0; }
static inline void livepatch_bsc1165631_geneve_cleanup(void) {}


struct sk_buff;
struct net_device;
struct flowi6;
struct ip_tunnel_info;

struct dst_entry *klpp_geneve_get_v6_dst(struct sk_buff *skb,
					   struct net_device *dev,
					   struct flowi6 *fl6,
					   const struct ip_tunnel_info *info);

#endif /* _LIVEPATCH_BSC1165631_GENEVE_H */

#ifndef _LIVEPATCH_BSC1165631_VXLAN_H
#define _LIVEPATCH_BSC1165631_VXLAN_H

int livepatch_bsc1165631_vxlan_init(void);
void livepatch_bsc1165631_vxlan_cleanup(void);


struct sk_buff;
struct net_device;
struct vxlan_rdst;

void klpp_vxlan_xmit_one(struct sk_buff *skb, struct net_device *dev,
			 __be32 default_vni, struct vxlan_rdst *rdst,
			 bool did_rsc);

int klpp_vxlan_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb);

#endif /* _LIVEPATCH_BSC1165631_VXLAN_H */

#ifndef _LIVEPATCH_BSC1160467_H
#define _LIVEPATCH_BSC1160467_H

int livepatch_bsc1160467_init(void);
void livepatch_bsc1160467_cleanup(void);



struct wiphy;
struct net_device;
struct cfg80211_connect_params;
struct lbs_private;
struct cfg80211_ibss_params;
struct cfg80211_bss;

int klpp_lbs_cfg_connect(struct wiphy *wiphy, struct net_device *dev,
			   struct cfg80211_connect_params *sme);

int klpp_lbs_ibss_join_existing(struct lbs_private *priv,
	struct cfg80211_ibss_params *params,
	struct cfg80211_bss *bss);

#endif /* _LIVEPATCH_BSC1160467_H */

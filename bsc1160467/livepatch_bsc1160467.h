#ifndef _LIVEPATCH_BSC1160467_H
#define _LIVEPATCH_BSC1160467_H

int livepatch_bsc1160467_init(void);
void livepatch_bsc1160467_cleanup(void);


struct lbs_private;
struct cfg80211_ibss_params;
struct cfg80211_bss;

u8 *klpp_add_ie_rates(u8 *tlv, const u8 *ie, int *nrates);

int klpp_lbs_ibss_join_existing(struct lbs_private *priv,
	struct cfg80211_ibss_params *params,
	struct cfg80211_bss *bss);

#endif /* _LIVEPATCH_BSC1160467_H */

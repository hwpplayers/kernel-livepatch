#ifndef _LIVEPATCH_BSC1136446_H
#define _LIVEPATCH_BSC1136446_H

int livepatch_bsc1136446_init(void);
void livepatch_bsc1136446_cleanup(void);

struct mwifiex_private;
struct cfg80211_beacon_data;
struct mwifiex_adapter;
struct mwifiex_bssdescriptor;

int klp_mwifiex_set_mgmt_ies(struct mwifiex_private *priv,
			     struct cfg80211_beacon_data *info);
int
klp_mwifiex_update_bss_desc_with_ie(struct mwifiex_adapter *adapter,
				    struct mwifiex_bssdescriptor *bss_entry);

#endif /* _LIVEPATCH_BSC1136446_H */

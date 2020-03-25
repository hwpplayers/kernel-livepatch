#ifndef _LIVEPATCH_BSC1159913_H
#define _LIVEPATCH_BSC1159913_H

int livepatch_bsc1159913_init(void);
void livepatch_bsc1159913_cleanup(void);


struct wiphy;
struct net_device;
struct station_parameters;
struct sta_info;
enum ieee80211_sta_state;

int klpp_ieee80211_add_station(struct wiphy *wiphy, struct net_device *dev,
				 const u8 *mac,
				 struct station_parameters *params);

int klpp_ieee80211_change_station(struct wiphy *wiphy,
				    struct net_device *dev, const u8 *mac,
				    struct station_parameters *params);

int klpp_sta_info_move_state(struct sta_info *sta,
			enum ieee80211_sta_state new_state);

#endif /* _LIVEPATCH_BSC1159913_H */

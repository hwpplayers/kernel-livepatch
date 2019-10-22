#ifndef _LIVEPATCH_BSC1153161_H
#define _LIVEPATCH_BSC1153161_H

int livepatch_bsc1153161_init(void);
void livepatch_bsc1153161_cleanup(void);


struct net_device;
struct iw_request_info;
struct iw_point;

int klpp_cfg80211_mgd_wext_giwessid(struct net_device *dev,
			       struct iw_request_info *info,
			       struct iw_point *data, char *ssid);

#endif /* _LIVEPATCH_BSC1153161_H */

/*
 * livepatch_bsc1153161
 *
 * Fix for CVE-2019-17133, bsc#1153161
 *
 *  Upstream commit:
 *  4ac2813cc867 ("cfg80211: wext: avoid copying malformed SSIDs")
 *
 *  SLE12-SP1 commit:
 *  7d5645d7476b5bfdee217f2f587de158313ce617
 *
 *  SLE12-SP2 and -SP3 commit:
 *  8f0099f1e07628ff807ec023c9f93f79db6a00a2
 *
 *  SLE12-SP4, SLE15 and SLE15-SP1 commit:
 *  5f20deadda7c451d1c2541ac482c9ed26e3daf3c
 *
 *
 *  Copyright (c) 2019 SUSE
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

#include <linux/export.h>
#include <linux/etherdevice.h>
#include <linux/slab.h>
#include <net/cfg80211.h>
#include <net/cfg80211-wext.h>
#include <net/iw_handler.h>
#include <linux/wireless.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/rbtree.h>
#include <linux/debugfs.h>
#include <linux/workqueue.h>
#include <net/cfg80211.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1153161.h"
#include "../kallsyms_relocs.h"

#if !IS_MODULE(CONFIG_CFG80211)
#error "Live patch supports only CONFIG_CFG80211=m"
#endif

#if !IS_ENABLED(CONFIG_CFG80211_WEXT)
#error "Live patch supports only CONFIG_CFG80211_WEXT=y"
#endif

#define LIVEPATCHED_MODULE "cfg80211"


static const u8 *(*klpe_ieee80211_bss_get_ie)(struct cfg80211_bss *bss, u8 ie);

/* from net/wireless/wext-compat.h */
int klpp_cfg80211_mgd_wext_giwessid(struct net_device *dev,
			       struct iw_request_info *info,
			       struct iw_point *data, char *ssid);

/* from net/wireless/core.h */
struct cfg80211_internal_bss {
	struct list_head list;
	struct list_head hidden_list;
	struct rb_node rbn;
	u64 ts_boottime;
	unsigned long ts;
	unsigned long refcount;
	atomic_t hold;

	/* time at the start of the reception of the first octet of the
	 * timestamp field of the last beacon/probe received for this BSS.
	 * The time is the TSF of the BSS specified by %parent_bssid.
	 */
	u64 parent_tsf;

	/* the BSS according to which %parent_tsf is set. This is set to
	 * the BSS that the interface that requested the scan was connected to
	 * when the beacon/probe was received.
	 */
	u8 parent_bssid[ETH_ALEN] __aligned(2);

	/* must be last because of priv member */
	struct cfg80211_bss pub;
};

static inline void wdev_lock(struct wireless_dev *wdev)
	__acquires(wdev)
{
	mutex_lock(&wdev->mtx);
	__acquire(wdev->mtx);
}

static inline void wdev_unlock(struct wireless_dev *wdev)
	__releases(wdev)
{
	__release(wdev->mtx);
	mutex_unlock(&wdev->mtx);
}

/* from net/wireless/wext-sme.c */
int klpp_cfg80211_mgd_wext_giwessid(struct net_device *dev,
			       struct iw_request_info *info,
			       struct iw_point *data, char *ssid)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	/*
	 * Fix CVE-2019-17133
	 *  +1 line
	 */
	int ret = 0;

	/* call only for station! */
	if (WARN_ON(wdev->iftype != NL80211_IFTYPE_STATION))
		return -EINVAL;

	data->flags = 0;

	wdev_lock(wdev);
	if (wdev->current_bss) {
		const u8 *ie;

		rcu_read_lock();
		ie = (*klpe_ieee80211_bss_get_ie)(&wdev->current_bss->pub,
					  WLAN_EID_SSID);
		if (ie) {
			data->flags = 1;
			data->length = ie[1];
			/*
			 * Fix CVE-2019-17133
			 *  -1 line, +4 lines
			 */
			if (data->length > IW_ESSID_MAX_SIZE)
				ret = -EINVAL;
			else
				memcpy(ssid, ie + 2, data->length);
		}
		rcu_read_unlock();
	} else if (wdev->wext.connect.ssid && wdev->wext.connect.ssid_len) {
		data->flags = 1;
		data->length = wdev->wext.connect.ssid_len;
		memcpy(ssid, wdev->wext.connect.ssid, data->length);
	}
	wdev_unlock(wdev);

	/*
	 * Fix CVE-2019-17133
	 *  -1 line, +1 line
	 */
	return ret;
}


static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "ieee80211_bss_get_ie", (void *)&klpe_ieee80211_bss_get_ie,
	  "cfg80211" },
};

static int livepatch_bsc1153161_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1153161_module_nb = {
	.notifier_call = livepatch_bsc1153161_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1153161_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1153161_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1153161_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1153161_module_nb);
}

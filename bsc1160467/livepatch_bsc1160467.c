/*
 * livepatch_bsc1160467
 *
 * Fix for CVE-2019-14897, bsc#1160467, CVE-2019-14896, bsc#1160468
 *
 *  Upstream commit:
 *  e5e884b42639c74b5b57dc277909915c0aefc8bb
 *
 *  SLE12-SP1 commit:
 *  172d338ede14624f24e79dd21616cedf7db2c6c2
 *
 *  SLE12-SP2 and -SP3 commit:
 *  356fb484967edddc9891dbe3d74ed0a769dc48ee
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE14-SP1 commit:
 *  f9891e0974ff4f89db80b4940fd1a787309ebb36
 *
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

#define pr_fmt(fmt) "libertas" ": " fmt

#include <linux/hardirq.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/ieee80211.h>
#include <net/cfg80211.h>
#include <asm/unaligned.h>
#include <linux/netdevice.h>
#include <linux/firmware.h>
#include <asm/unaligned.h>
#include <linux/netdevice.h>
#include <linux/nl80211.h>
#include <net/cfg80211.h>
#include <linux/if_ether.h>
#include <linux/ieee80211.h>
#include <asm/byteorder.h>
#include <linux/spinlock.h>
#include <linux/kfifo.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1160467.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "libertas"


/* from include/net/cfg80211.h */
static const u8 *(*klpe_ieee80211_bss_get_ie)(struct cfg80211_bss *bss, u8 ie);

static struct cfg80211_bss *(*klpe_cfg80211_get_bss)(struct wiphy *wiphy,
				      struct ieee80211_channel *channel,
				      const u8 *bssid,
				      const u8 *ssid, size_t ssid_len,
				      enum ieee80211_bss_type bss_type,
				      enum ieee80211_privacy privacy);

static void (*klpe_cfg80211_put_bss)(struct wiphy *wiphy, struct cfg80211_bss *bss);

static void (*klpe_cfg80211_connect_done)(struct net_device *dev,
			   struct cfg80211_connect_resp_params *params,
			   gfp_t gfp);

/* resolve reference to cfg80211_connect_done() */
static inline void
klpr_cfg80211_connect_bss(struct net_device *dev, const u8 *bssid,
		     struct cfg80211_bss *bss, const u8 *req_ie,
		     size_t req_ie_len, const u8 *resp_ie,
		     size_t resp_ie_len, int status, gfp_t gfp,
		     enum nl80211_timeout_reason timeout_reason)
{
	struct cfg80211_connect_resp_params params;

	memset(&params, 0, sizeof(params));
	params.status = status;
	params.bssid = bssid;
	params.bss = bss;
	params.req_ie = req_ie;
	params.req_ie_len = req_ie_len;
	params.resp_ie = resp_ie;
	params.resp_ie_len = resp_ie_len;
	params.timeout_reason = timeout_reason;

	(*klpe_cfg80211_connect_done)(dev, &params, gfp);
}

static inline void
klpr_cfg80211_connect_result(struct net_device *dev, const u8 *bssid,
			const u8 *req_ie, size_t req_ie_len,
			const u8 *resp_ie, size_t resp_ie_len,
			u16 status, gfp_t gfp)
{
	klpr_cfg80211_connect_bss(dev, bssid, NULL, req_ie, req_ie_len, resp_ie,
			     resp_ie_len, status, gfp,
			     NL80211_TIMEOUT_UNSPECIFIED);
}

static unsigned int (*klpe_ieee80211_get_num_supported_channels)(struct wiphy *wiphy);


/* from drivers/net/wireless/marvell/libertas/decl.h */
struct lbs_private;
typedef void (*lbs_fw_cb)(struct lbs_private *priv, int ret,
		const struct firmware *helper, const struct firmware *mainfw);


/* from drivers/net/wireless/marvell/libertas/types.h */
struct ieee_ie_header {
	u8 id;
	u8 len;
} __packed;

struct ieee_ie_ibss_param_set {
	struct ieee_ie_header header;

	__le16 atimwindow;
} __packed;

struct ieee_ie_ds_param_set {
	struct ieee_ie_header header;

	u8 channel;
} __packed;

#define PROPRIETARY_TLV_BASE_ID		0x0100

#define TLV_TYPE_SSID				0x0000
#define TLV_TYPE_RATES				0x0001

#define TLV_TYPE_PHY_DS				0x0003
#define TLV_TYPE_CF				    0x0004

#define TLV_TYPE_AUTH_TYPE          (PROPRIETARY_TLV_BASE_ID + 31)

struct mrvl_ie_header {
	__le16 type;
	__le16 len;
} __packed;

struct mrvl_ie_rates_param_set {
	struct mrvl_ie_header header;
	u8 rates[1];
} __packed;

struct mrvl_ie_ssid_param_set {
	struct mrvl_ie_header header;
	u8 ssid[1];
} __packed;

struct mrvl_ie_cf_param_set {
	struct mrvl_ie_header header;
	u8 cfpcnt;
	u8 cfpperiod;
	__le16 cfpmaxduration;
	__le16 cfpdurationremaining;
} __packed;

struct mrvl_ie_ds_param_set {
	struct mrvl_ie_header header;
	u8 channel;
} __packed;

struct mrvl_ie_auth_type {
	struct mrvl_ie_header header;
	__le16 auth;
} __packed;


/* from drivers/net/wireless/marvell/libertas/defs.h */
#define LBS_DEB_LL(grp, grpnam, fmt, args...) do {} while (0)

#define lbs_deb_scan(fmt, args...)      LBS_DEB_LL(LBS_DEB_SCAN, " scan", fmt, ##args)
#define lbs_deb_assoc(fmt, args...)     LBS_DEB_LL(LBS_DEB_ASSOC, " assoc", fmt, ##args)
#define lbs_deb_join(fmt, args...)      LBS_DEB_LL(LBS_DEB_JOIN, " join", fmt, ##args)

#define lbs_deb_hex(grp,prompt,buf,len)	do {} while (0)

#define MRVDRV_MAX_MULTICAST_LIST_SIZE	32

#define MRVDRV_ASSOCIATION_TIME_OUT	255

#define	LBS_UPLD_SIZE			2312

#define MRVDRV_DEFAULT_LISTEN_INTERVAL		10

#define MRVL_FW_MAJOR_REV(x)				((x)>>24)

#define MAX_RATES			14

enum LBS_MEDIA_STATE {
	LBS_CONNECTED,
	LBS_DISCONNECTED
};

enum KEY_TYPE_ID {
	KEY_TYPE_ID_WEP = 0,
	KEY_TYPE_ID_TKIP,
	KEY_TYPE_ID_AES
};

enum KEY_INFO_WPA {
	KEY_INFO_WPA_MCAST = 0x01,
	KEY_INFO_WPA_UNICAST = 0x02,
	KEY_INFO_WPA_ENABLED = 0x04
};


/* from drivers/net/wireless/marvell/libertas/host.h */
#define CMD_802_11_AUTHENTICATE                 0x0011

#define CMD_802_11_ASSOCIATE                    0x0050

#define CMD_802_11_AD_HOC_JOIN                  0x002c

#define CMD_BSS_TYPE_IBSS                       0x0002

#define CMD_SCAN_PROBE_DELAY_TIME               0

#define CMD_ACT_MAC_WEP_ENABLE                  0x0008

#define RADIO_PREAMBLE_SHORT                    0x02

struct cmd_header {
	__le16 command;
	__le16 size;
	__le16 seqnum;
	__le16 result;
} __packed;

struct cmd_ds_802_11_authenticate {
	struct cmd_header hdr;

	u8 bssid[ETH_ALEN];
	u8 authtype;
	u8 reserved[10];
} __packed;

struct cmd_ds_802_11_associate {
	struct cmd_header hdr;

	u8 bssid[6];
	__le16 capability;
	__le16 listeninterval;
	__le16 bcnperiod;
	u8 dtimperiod;
	u8 iebuf[512];    /* Enough for required and most optional IEs */
} __packed;

struct cmd_ds_802_11_associate_response {
	struct cmd_header hdr;

	__le16 capability;
	__le16 statuscode;
	__le16 aid;
	u8 iebuf[512];
} __packed;

struct adhoc_bssdesc {
	u8 bssid[ETH_ALEN];
	u8 ssid[IEEE80211_MAX_SSID_LEN];
	u8 type;
	__le16 beaconperiod;
	u8 dtimperiod;
	__le64 timestamp;
	__le64 localtime;
	struct ieee_ie_ds_param_set ds;
	u8 reserved1[4];
	struct ieee_ie_ibss_param_set ibss;
	u8 reserved2[4];
	__le16 capability;
	u8 rates[MAX_RATES];

	/*
	 * DO NOT ADD ANY FIELDS TO THIS STRUCTURE. It is used below in the
	 * Adhoc join command and will cause a binary layout mismatch with
	 * the firmware
	 */
} __packed;

struct cmd_ds_802_11_ad_hoc_join {
	struct cmd_header hdr;

	struct adhoc_bssdesc bss;
	__le16 failtimeout;   /* Reserved on v9 and later */
	__le16 probedelay;    /* Reserved on v9 and later */
} __packed;


/* from drivers/net/wireless/marvell/libertas/dev.h */
struct lbs_mesh_stats {
	u32	fwd_bcast_cnt;		/* Fwd: Broadcast counter */
	u32	fwd_unicast_cnt;	/* Fwd: Unicast counter */
	u32	fwd_drop_ttl;		/* Fwd: TTL zero */
	u32	fwd_drop_rbt;		/* Fwd: Recently Broadcasted */
	u32	fwd_drop_noroute; 	/* Fwd: No route to Destination */
	u32	fwd_drop_nobuf;		/* Fwd: Run out of internal buffers */
	u32	drop_blind;		/* Rx:  Dropped by blinding table */
	u32	tx_failed_cnt;		/* Tx:  Failed transmissions */
};

struct lbs_private {

	/* Basic networking */
	struct net_device *dev;
	u32 connect_status;
	struct work_struct mcast_work;
	u32 nr_of_multicastmacaddr;
	u8 multicastlist[MRVDRV_MAX_MULTICAST_LIST_SIZE][ETH_ALEN];

	/* CFG80211 */
	struct wireless_dev *wdev;
	bool wiphy_registered;
	struct cfg80211_scan_request *scan_req;
	u8 assoc_bss[ETH_ALEN];
	u8 country_code[IEEE80211_COUNTRY_STRING_LEN];
	u8 disassoc_reason;

	/* Mesh */
	struct net_device *mesh_dev; /* Virtual device */
#ifdef CONFIG_LIBERTAS_MESH
	struct lbs_mesh_stats mstats;
	uint16_t mesh_tlv;
	u8 mesh_ssid[IEEE80211_MAX_SSID_LEN + 1];
	u8 mesh_ssid_len;
	u8 mesh_channel;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct dentry *debugfs_dir;
	struct dentry *debugfs_debug;
	struct dentry *debugfs_files[6];
	struct dentry *events_dir;
	struct dentry *debugfs_events_files[6];
	struct dentry *regs_dir;
	struct dentry *debugfs_regs_files[6];

	/* Hardware debugging */
	u32 mac_offset;
	u32 bbp_offset;
	u32 rf_offset;

	/* Power management */
	u16 psmode;
	u32 psstate;
	u8 needtowakeup;

	/* Deep sleep */
	int is_deep_sleep;
	int deep_sleep_required;
	int is_auto_deep_sleep_enabled;
	int wakeup_dev_required;
	int is_activity_detected;
	int auto_deep_sleep_timeout; /* in ms */
	wait_queue_head_t ds_awake_q;
	struct timer_list auto_deepsleep_timer;

	/* Host sleep*/
	int is_host_sleep_configured;
	int is_host_sleep_activated;
	wait_queue_head_t host_sleep_q;

	/* Hardware access */
	void *card;
	bool iface_running;
	u8 is_polling; /* host has to poll the card irq */
	u8 fw_ready;
	u8 surpriseremoved;
	u8 setup_fw_on_resume;
	u8 power_up_on_resume;
	int (*hw_host_to_card) (struct lbs_private *priv, u8 type, u8 *payload, u16 nb);
	void (*reset_card) (struct lbs_private *priv);
	int (*power_save) (struct lbs_private *priv);
	int (*power_restore) (struct lbs_private *priv);
	int (*enter_deep_sleep) (struct lbs_private *priv);
	int (*exit_deep_sleep) (struct lbs_private *priv);
	int (*reset_deep_sleep_wakeup) (struct lbs_private *priv);

	/* Adapter info (from EEPROM) */
	u32 fwrelease;
	u32 fwcapinfo;
	u16 regioncode;
	u8 current_addr[ETH_ALEN];
	u8 copied_hwaddr;

	/* Command download */
	u8 dnld_sent;
	/* bit0 1/0=data_sent/data_tx_done,
	   bit1 1/0=cmd_sent/cmd_tx_done,
	   all other bits reserved 0 */
	u16 seqnum;
	struct cmd_ctrl_node *cmd_array;
	struct cmd_ctrl_node *cur_cmd;
	struct list_head cmdfreeq;    /* free command buffers */
	struct list_head cmdpendingq; /* pending command buffers */
	struct timer_list command_timer;
	int cmd_timed_out;

	/* Command responses sent from the hardware to the driver */
	u8 resp_idx;
	u8 resp_buf[2][LBS_UPLD_SIZE];
	u32 resp_len[2];

	/* Events sent from hardware to driver */
	struct kfifo event_fifo;

	/* thread to service interrupts */
	struct task_struct *main_thread;
	wait_queue_head_t waitq;
	struct workqueue_struct *work_thread;

	/* Encryption stuff */
	u8 authtype_auto;
	u8 wep_tx_key;
	u8 wep_key[4][WLAN_KEY_LEN_WEP104];
	u8 wep_key_len[4];

	/* Wake On LAN */
	uint32_t wol_criteria;
	uint8_t wol_gpio;
	uint8_t wol_gap;
	bool ehs_remove_supported;

	/* Transmitting */
	int tx_pending_len;		/* -1 while building packet */
	u8 tx_pending_buf[LBS_UPLD_SIZE];
	/* protected by hard_start_xmit serialization */
	u8 txretrycount;
	struct sk_buff *currenttxskb;
	struct timer_list tx_lockup_timer;

	/* Locks */
	struct mutex lock;
	spinlock_t driver_lock;

	/* NIC/link operation characteristics */
	u16 mac_control;
	u8 radio_on;
	u8 cur_rate;
	u8 channel;
	s16 txpower_cur;
	s16 txpower_min;
	s16 txpower_max;

	/* Scanning */
	struct delayed_work scan_work;
	int scan_channel;
	/* Queue of things waiting for scan completion */
	wait_queue_head_t scan_q;
	/* Whether the scan was initiated internally and not by cfg80211 */
	bool internal_scan;

	/* Firmware load */
	u32 fw_model;
	wait_queue_head_t fw_waitq;
	struct device *fw_device;
	const struct firmware *helper_fw;
	const struct lbs_fw_table *fw_table;
	const struct lbs_fw_table *fw_iter;
	lbs_fw_cb fw_callback;
};


/* from drivers/net/wireless/marvell/libertas/cmd.h */
static int (*klpe___lbs_cmd)(struct lbs_private *priv, uint16_t command,
	      struct cmd_header *in_cmd, int in_cmd_size,
	      int (*callback)(struct lbs_private *, unsigned long, struct cmd_header *),
	      unsigned long callback_arg);

static int (*klpe_lbs_cmd_copyback)(struct lbs_private *priv, unsigned long extra,
		     struct cmd_header *resp);

/* resolve reference to __lbs_cmd() */
#define klpr_lbs_cmd(priv, cmdnr, cmd, cb, cb_arg)	({		\
	uint16_t __sz = le16_to_cpu((cmd)->hdr.size);		\
	(cmd)->hdr.size = cpu_to_le16(sizeof(*(cmd)));		\
	klpe___lbs_cmd(priv, cmdnr, &(cmd)->hdr, __sz, cb, cb_arg);	\
})

/* resolve references to __lbs_cmd() and lbs_cmd_copyback() */
#define klpr_lbs_cmd_with_response(priv, cmdnr, cmd)	\
	klpr_lbs_cmd(priv, cmdnr, cmd, (*klpe_lbs_cmd_copyback), (unsigned long) (cmd))

static int (*klpe_lbs_set_radio)(struct lbs_private *priv, u8 preamble, u8 radio_on);

static void (*klpe_lbs_set_mac_control)(struct lbs_private *priv);

/* from drivers/net/wireless/marvell/libertas/cfg.c */
static struct ieee80211_rate (*klpe_lbs_rates)[12];

static int lbs_auth_to_authtype(enum nl80211_auth_type auth_type)
{
	int ret = -ENOTSUPP;

	switch (auth_type) {
	case NL80211_AUTHTYPE_OPEN_SYSTEM:
	case NL80211_AUTHTYPE_SHARED_KEY:
		ret = auth_type;
		break;
	case NL80211_AUTHTYPE_AUTOMATIC:
		ret = NL80211_AUTHTYPE_OPEN_SYSTEM;
		break;
	case NL80211_AUTHTYPE_NETWORK_EAP:
		ret = 0x80;
		break;
	default:
		/* silence compiler */
		break;
	}
	return ret;
}

static int klpr_lbs_add_rates(u8 *rates)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE((*klpe_lbs_rates)); i++) {
		u8 rate = (*klpe_lbs_rates)[i].bitrate / 5;
		if (rate == 0x02 || rate == 0x04 ||
		    rate == 0x0b || rate == 0x16)
			rate |= 0x80;
		rates[i] = rate;
	}
	return ARRAY_SIZE((*klpe_lbs_rates));
}

#define LBS_MAX_SSID_TLV_SIZE			\
	(sizeof(struct mrvl_ie_header)		\
	 + IEEE80211_MAX_SSID_LEN)

static int lbs_add_ssid_tlv(u8 *tlv, const u8 *ssid, int ssid_len)
{
	struct mrvl_ie_ssid_param_set *ssid_tlv = (void *)tlv;

	/*
	 * TLV-ID SSID  00 00
	 * length       06 00
	 * ssid         4d 4e 54 45 53 54
	 */
	ssid_tlv->header.type = cpu_to_le16(TLV_TYPE_SSID);
	ssid_tlv->header.len = cpu_to_le16(ssid_len);
	memcpy(ssid_tlv->ssid, ssid, ssid_len);
	return sizeof(ssid_tlv->header) + ssid_len;
}

/* patched, inlined */
static u8 *
klpp_add_ie_rates(u8 *tlv, const u8 *ie, int *nrates)
{
	int hw, ap, ap_max = ie[1];
	u8 hw_rate;

	/*
	 * Fix CVE-2019-14896
	 *  +4 lines
	 */
	if (ap_max > MAX_RATES) {
		lbs_deb_assoc("invalid rates\n");
		return tlv;
	}

	/* Advance past IE header */
	ie += 2;

	lbs_deb_hex(LBS_DEB_ASSOC, "AP IE Rates", (u8 *) ie, ap_max);

	for (hw = 0; hw < ARRAY_SIZE((*klpe_lbs_rates)); hw++) {
		hw_rate = (*klpe_lbs_rates)[hw].bitrate / 5;
		for (ap = 0; ap < ap_max; ap++) {
			if (hw_rate == (ie[ap] & 0x7f)) {
				*tlv++ = ie[ap];
				*nrates = *nrates + 1;
			}
		}
	}
	return tlv;
}

/* patched, inlined, calls inlined add_ie_rates() */
static int klpp_lbs_add_common_rates_tlv(u8 *tlv, struct cfg80211_bss *bss)
{
	struct mrvl_ie_rates_param_set *rate_tlv = (void *)tlv;
	const u8 *rates_eid, *ext_rates_eid;
	int n = 0;

	rcu_read_lock();
	rates_eid = (*klpe_ieee80211_bss_get_ie)(bss, WLAN_EID_SUPP_RATES);
	ext_rates_eid = (*klpe_ieee80211_bss_get_ie)(bss, WLAN_EID_EXT_SUPP_RATES);

	/*
	 * 01 00                   TLV_TYPE_RATES
	 * 04 00                   len
	 * 82 84 8b 96             rates
	 */
	rate_tlv->header.type = cpu_to_le16(TLV_TYPE_RATES);
	tlv += sizeof(rate_tlv->header);

	/* Add basic rates */
	if (rates_eid) {
		tlv = klpp_add_ie_rates(tlv, rates_eid, &n);

		/* Add extended rates, if any */
		if (ext_rates_eid)
			tlv = klpp_add_ie_rates(tlv, ext_rates_eid, &n);
	} else {
		lbs_deb_assoc("assoc: bss had no basic rate IE\n");
		/* Fallback: add basic 802.11b rates */
		*tlv++ = 0x82;
		*tlv++ = 0x84;
		*tlv++ = 0x8b;
		*tlv++ = 0x96;
		n = 4;
	}
	rcu_read_unlock();

	rate_tlv->header.len = cpu_to_le16(n);
	return sizeof(rate_tlv->header) + n;
}

#define LBS_MAX_AUTH_TYPE_TLV_SIZE \
	sizeof(struct mrvl_ie_auth_type)

static int lbs_add_auth_type_tlv(u8 *tlv, enum nl80211_auth_type auth_type)
{
	struct mrvl_ie_auth_type *auth = (void *) tlv;

	/*
	 * 1f 01  TLV_TYPE_AUTH_TYPE
	 * 01 00  len
	 * 01     auth type
	 */
	auth->header.type = cpu_to_le16(TLV_TYPE_AUTH_TYPE);
	auth->header.len = cpu_to_le16(sizeof(*auth)-sizeof(auth->header));
	auth->auth = cpu_to_le16(lbs_auth_to_authtype(auth_type));
	return sizeof(*auth);
}

#define LBS_MAX_CHANNEL_TLV_SIZE \
	sizeof(struct mrvl_ie_header)

static int lbs_add_channel_tlv(u8 *tlv, u8 channel)
{
	struct mrvl_ie_ds_param_set *ds = (void *) tlv;

	/*
	 * 03 00  TLV_TYPE_PHY_DS
	 * 01 00  len
	 * 06     channel
	 */
	ds->header.type = cpu_to_le16(TLV_TYPE_PHY_DS);
	ds->header.len = cpu_to_le16(sizeof(*ds)-sizeof(ds->header));
	ds->channel = channel;
	return sizeof(*ds);
}

#define LBS_MAX_CF_PARAM_TLV_SIZE		\
	sizeof(struct mrvl_ie_header)

static int lbs_add_cf_param_tlv(u8 *tlv)
{
	struct mrvl_ie_cf_param_set *cf = (void *)tlv;

	/*
	 * 04 00  TLV_TYPE_CF
	 * 06 00  len
	 * 00     cfpcnt
	 * 00     cfpperiod
	 * 00 00  cfpmaxduration
	 * 00 00  cfpdurationremaining
	 */
	cf->header.type = cpu_to_le16(TLV_TYPE_CF);
	cf->header.len = cpu_to_le16(sizeof(*cf)-sizeof(cf->header));
	return sizeof(*cf);
}

#define LBS_MAX_WPA_TLV_SIZE			\
	(sizeof(struct mrvl_ie_header)		\
	 + 128 /* TODO: I guessed the size */)

static int lbs_add_wpa_tlv(u8 *tlv, const u8 *ie, u8 ie_len)
{
	size_t tlv_len;

	/*
	 * We need just convert an IE to an TLV. IEs use u8 for the header,
	 *   u8      type
	 *   u8      len
	 *   u8[]    data
	 * but TLVs use __le16 instead:
	 *   __le16  type
	 *   __le16  len
	 *   u8[]    data
	 */
	*tlv++ = *ie++;
	*tlv++ = 0;
	tlv_len = *tlv++ = *ie++;
	*tlv++ = 0;
	while (tlv_len--)
		*tlv++ = *ie++;
	/* the TLV is two bytes larger than the IE */
	return ie_len + 2;
}

static void _internal_start_scan(struct lbs_private *priv, bool internal,
	struct cfg80211_scan_request *request)
{
	lbs_deb_scan("scan: ssids %d, channels %d, ie_len %zd\n",
		request->n_ssids, request->n_channels, request->ie_len);

	priv->scan_channel = 0;
	priv->scan_req = request;
	priv->internal_scan = internal;

	queue_delayed_work(priv->work_thread, &priv->scan_work,
		msecs_to_jiffies(50));
}

static int (*klpe_lbs_remove_wep_keys)(struct lbs_private *priv);

static int (*klpe_lbs_set_wep_keys)(struct lbs_private *priv);

static int (*klpe_lbs_enable_rsn)(struct lbs_private *priv, int enable);

static int (*klpe_lbs_set_key_material)(struct lbs_private *priv,
				int key_type, int key_info,
				const u8 *key, u16 key_len);

static int klpr_lbs_set_authtype(struct lbs_private *priv,
			    struct cfg80211_connect_params *sme)
{
	struct cmd_ds_802_11_authenticate cmd;
	int ret;

	/*
	 * cmd        11 00
	 * size       19 00
	 * sequence   xx xx
	 * result     00 00
	 * BSS id     00 13 19 80 da 30
	 * auth type  00
	 * reserved   00 00 00 00 00 00 00 00 00 00
	 */
	memset(&cmd, 0, sizeof(cmd));
	cmd.hdr.size = cpu_to_le16(sizeof(cmd));
	if (sme->bssid)
		memcpy(cmd.bssid, sme->bssid, ETH_ALEN);
	/* convert auth_type */
	ret = lbs_auth_to_authtype(sme->auth_type);
	if (ret < 0)
		goto done;

	cmd.authtype = ret;
	ret = klpr_lbs_cmd_with_response(priv, CMD_802_11_AUTHENTICATE, &cmd);

 done:
	return ret;
}

#define LBS_ASSOC_MAX_CMD_SIZE                     \
	(sizeof(struct cmd_ds_802_11_associate)    \
	 - 512 /* cmd_ds_802_11_associate.iebuf */ \
	 + LBS_MAX_SSID_TLV_SIZE                   \
	 + LBS_MAX_CHANNEL_TLV_SIZE                \
	 + LBS_MAX_CF_PARAM_TLV_SIZE               \
	 + LBS_MAX_AUTH_TYPE_TLV_SIZE              \
	 + LBS_MAX_WPA_TLV_SIZE)

/* patched, inlined on x86_64, calls inlined lbs_add_common_rates_tlv() */
static int klpp_lbs_associate(struct lbs_private *priv,
		struct cfg80211_bss *bss,
		struct cfg80211_connect_params *sme)
{
	struct cmd_ds_802_11_associate_response *resp;
	struct cmd_ds_802_11_associate *cmd = kzalloc(LBS_ASSOC_MAX_CMD_SIZE,
						      GFP_KERNEL);
	const u8 *ssid_eid;
	size_t len, resp_ie_len;
	int status;
	int ret;
	u8 *pos;
	u8 *tmp;

	if (!cmd) {
		ret = -ENOMEM;
		goto done;
	}
	pos = &cmd->iebuf[0];

	/*
	 * cmd              50 00
	 * length           34 00
	 * sequence         xx xx
	 * result           00 00
	 * BSS id           00 13 19 80 da 30
	 * capabilities     11 00
	 * listen interval  0a 00
	 * beacon interval  00 00
	 * DTIM period      00
	 * TLVs             xx   (up to 512 bytes)
	 */
	cmd->hdr.command = cpu_to_le16(CMD_802_11_ASSOCIATE);

	/* Fill in static fields */
	memcpy(cmd->bssid, bss->bssid, ETH_ALEN);
	cmd->listeninterval = cpu_to_le16(MRVDRV_DEFAULT_LISTEN_INTERVAL);
	cmd->capability = cpu_to_le16(bss->capability);

	/* add SSID TLV */
	rcu_read_lock();
	ssid_eid = (*klpe_ieee80211_bss_get_ie)(bss, WLAN_EID_SSID);
	if (ssid_eid)
		pos += lbs_add_ssid_tlv(pos, ssid_eid + 2, ssid_eid[1]);
	else
		lbs_deb_assoc("no SSID\n");
	rcu_read_unlock();

	/* add DS param TLV */
	if (bss->channel)
		pos += lbs_add_channel_tlv(pos, bss->channel->hw_value);
	else
		lbs_deb_assoc("no channel\n");

	/* add (empty) CF param TLV */
	pos += lbs_add_cf_param_tlv(pos);

	/* add rates TLV */
	tmp = pos + 4; /* skip Marvell IE header */
	pos += klpp_lbs_add_common_rates_tlv(pos, bss);
	lbs_deb_hex(LBS_DEB_ASSOC, "Common Rates", tmp, pos - tmp);

	/* add auth type TLV */
	if (MRVL_FW_MAJOR_REV(priv->fwrelease) >= 9)
		pos += lbs_add_auth_type_tlv(pos, sme->auth_type);

	/* add WPA/WPA2 TLV */
	if (sme->ie && sme->ie_len)
		pos += lbs_add_wpa_tlv(pos, sme->ie, sme->ie_len);

	len = (sizeof(*cmd) - sizeof(cmd->iebuf)) +
		(u16)(pos - (u8 *) &cmd->iebuf);
	cmd->hdr.size = cpu_to_le16(len);

	lbs_deb_hex(LBS_DEB_ASSOC, "ASSOC_CMD", (u8 *) cmd,
			le16_to_cpu(cmd->hdr.size));

	/* store for later use */
	memcpy(priv->assoc_bss, bss->bssid, ETH_ALEN);

	ret = klpr_lbs_cmd_with_response(priv, CMD_802_11_ASSOCIATE, cmd);
	if (ret)
		goto done;

	/* generate connect message to cfg80211 */

	resp = (void *) cmd; /* recast for easier field access */
	status = le16_to_cpu(resp->statuscode);

	/* Older FW versions map the IEEE 802.11 Status Code in the association
	 * response to the following values returned in resp->statuscode:
	 *
	 *    IEEE Status Code                Marvell Status Code
	 *    0                       ->      0x0000 ASSOC_RESULT_SUCCESS
	 *    13                      ->      0x0004 ASSOC_RESULT_AUTH_REFUSED
	 *    14                      ->      0x0004 ASSOC_RESULT_AUTH_REFUSED
	 *    15                      ->      0x0004 ASSOC_RESULT_AUTH_REFUSED
	 *    16                      ->      0x0004 ASSOC_RESULT_AUTH_REFUSED
	 *    others                  ->      0x0003 ASSOC_RESULT_REFUSED
	 *
	 * Other response codes:
	 *    0x0001 -> ASSOC_RESULT_INVALID_PARAMETERS (unused)
	 *    0x0002 -> ASSOC_RESULT_TIMEOUT (internal timer expired waiting for
	 *                                    association response from the AP)
	 */
	if (MRVL_FW_MAJOR_REV(priv->fwrelease) <= 8) {
		switch (status) {
		case 0:
			break;
		case 1:
			lbs_deb_assoc("invalid association parameters\n");
			status = WLAN_STATUS_CAPS_UNSUPPORTED;
			break;
		case 2:
			lbs_deb_assoc("timer expired while waiting for AP\n");
			status = WLAN_STATUS_AUTH_TIMEOUT;
			break;
		case 3:
			lbs_deb_assoc("association refused by AP\n");
			status = WLAN_STATUS_ASSOC_DENIED_UNSPEC;
			break;
		case 4:
			lbs_deb_assoc("authentication refused by AP\n");
			status = WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION;
			break;
		default:
			lbs_deb_assoc("association failure %d\n", status);
			/* v5 OLPC firmware does return the AP status code if
			 * it's not one of the values above.  Let that through.
			 */
			break;
		}
	}

	lbs_deb_assoc("status %d, statuscode 0x%04x, capability 0x%04x, "
		      "aid 0x%04x\n", status, le16_to_cpu(resp->statuscode),
		      le16_to_cpu(resp->capability), le16_to_cpu(resp->aid));

	resp_ie_len = le16_to_cpu(resp->hdr.size)
		- sizeof(resp->hdr)
		- 6;
	klpr_cfg80211_connect_result(priv->dev,
				priv->assoc_bss,
				sme->ie, sme->ie_len,
				resp->iebuf, resp_ie_len,
				status,
				GFP_KERNEL);

	if (status == 0) {
		/* TODO: get rid of priv->connect_status */
		priv->connect_status = LBS_CONNECTED;
		netif_carrier_on(priv->dev);
		if (!priv->tx_pending_len)
			netif_tx_wake_all_queues(priv->dev);
	}

	kfree(cmd);
done:
	return ret;
}

static struct cfg80211_scan_request *
klpr__new_connect_scan_req(struct wiphy *wiphy, struct cfg80211_connect_params *sme)
{
	struct cfg80211_scan_request *creq = NULL;
	int i, n_channels = (*klpe_ieee80211_get_num_supported_channels)(wiphy);
	enum nl80211_band band;

	creq = kzalloc(sizeof(*creq) + sizeof(struct cfg80211_ssid) +
		       n_channels * sizeof(void *),
		       GFP_ATOMIC);
	if (!creq)
		return NULL;

	/* SSIDs come after channels */
	creq->ssids = (void *)&creq->channels[n_channels];
	creq->n_channels = n_channels;
	creq->n_ssids = 1;

	/* Scan all available channels */
	i = 0;
	for (band = 0; band < NUM_NL80211_BANDS; band++) {
		int j;

		if (!wiphy->bands[band])
			continue;

		for (j = 0; j < wiphy->bands[band]->n_channels; j++) {
			/* ignore disabled channels */
			if (wiphy->bands[band]->channels[j].flags &
						IEEE80211_CHAN_DISABLED)
				continue;

			creq->channels[i] = &wiphy->bands[band]->channels[j];
			i++;
		}
	}
	if (i) {
		/* Set real number of channels specified in creq->channels[] */
		creq->n_channels = i;

		/* Scan for the SSID we're going to connect to */
		memcpy(creq->ssids[0].ssid, sme->ssid, sme->ssid_len);
		creq->ssids[0].ssid_len = sme->ssid_len;
	} else {
		/* No channels found... */
		kfree(creq);
		creq = NULL;
	}

	return creq;
}

/* patched, calls inlined lbs_associate() */
int klpp_lbs_cfg_connect(struct wiphy *wiphy, struct net_device *dev,
			   struct cfg80211_connect_params *sme)
{
	struct lbs_private *priv = wiphy_priv(wiphy);
	struct cfg80211_bss *bss = NULL;
	int ret = 0;
	u8 preamble = RADIO_PREAMBLE_SHORT;

	if (dev == priv->mesh_dev)
		return -EOPNOTSUPP;

	if (!sme->bssid) {
		struct cfg80211_scan_request *creq;

		/*
		 * Scan for the requested network after waiting for existing
		 * scans to finish.
		 */
		lbs_deb_assoc("assoc: waiting for existing scans\n");
		wait_event_interruptible_timeout(priv->scan_q,
						 (priv->scan_req == NULL),
						 (15 * HZ));

		creq = klpr__new_connect_scan_req(wiphy, sme);
		if (!creq) {
			ret = -EINVAL;
			goto done;
		}

		lbs_deb_assoc("assoc: scanning for compatible AP\n");
		_internal_start_scan(priv, true, creq);

		lbs_deb_assoc("assoc: waiting for scan to complete\n");
		wait_event_interruptible_timeout(priv->scan_q,
						 (priv->scan_req == NULL),
						 (15 * HZ));
		lbs_deb_assoc("assoc: scanning completed\n");
	}

	/* Find the BSS we want using available scan results */
	bss = (*klpe_cfg80211_get_bss)(wiphy, sme->channel, sme->bssid,
		sme->ssid, sme->ssid_len, IEEE80211_BSS_TYPE_ESS,
		IEEE80211_PRIVACY_ANY);
	if (!bss) {
		wiphy_err(wiphy, "assoc: bss %pM not in scan results\n",
			  sme->bssid);
		ret = -ENOENT;
		goto done;
	}
	lbs_deb_assoc("trying %pM\n", bss->bssid);
	lbs_deb_assoc("cipher 0x%x, key index %d, key len %d\n",
		      sme->crypto.cipher_group,
		      sme->key_idx, sme->key_len);

	/* As this is a new connection, clear locally stored WEP keys */
	priv->wep_tx_key = 0;
	memset(priv->wep_key, 0, sizeof(priv->wep_key));
	memset(priv->wep_key_len, 0, sizeof(priv->wep_key_len));

	/* set/remove WEP keys */
	switch (sme->crypto.cipher_group) {
	case WLAN_CIPHER_SUITE_WEP40:
	case WLAN_CIPHER_SUITE_WEP104:
		/* Store provided WEP keys in priv-> */
		priv->wep_tx_key = sme->key_idx;
		priv->wep_key_len[sme->key_idx] = sme->key_len;
		memcpy(priv->wep_key[sme->key_idx], sme->key, sme->key_len);
		/* Set WEP keys and WEP mode */
		(*klpe_lbs_set_wep_keys)(priv);
		priv->mac_control |= CMD_ACT_MAC_WEP_ENABLE;
		(*klpe_lbs_set_mac_control)(priv);
		/* No RSN mode for WEP */
		(*klpe_lbs_enable_rsn)(priv, 0);
		break;
	case 0: /* there's no WLAN_CIPHER_SUITE_NONE definition */
		/*
		 * If we don't have no WEP, no WPA and no WPA2,
		 * we remove all keys like in the WPA/WPA2 setup,
		 * we just don't set RSN.
		 *
		 * Therefore: fall-through
		 */
	case WLAN_CIPHER_SUITE_TKIP:
	case WLAN_CIPHER_SUITE_CCMP:
		/* Remove WEP keys and WEP mode */
		(*klpe_lbs_remove_wep_keys)(priv);
		priv->mac_control &= ~CMD_ACT_MAC_WEP_ENABLE;
		(*klpe_lbs_set_mac_control)(priv);

		/* clear the WPA/WPA2 keys */
		(*klpe_lbs_set_key_material)(priv,
			KEY_TYPE_ID_WEP, /* doesn't matter */
			KEY_INFO_WPA_UNICAST,
			NULL, 0);
		(*klpe_lbs_set_key_material)(priv,
			KEY_TYPE_ID_WEP, /* doesn't matter */
			KEY_INFO_WPA_MCAST,
			NULL, 0);
		/* RSN mode for WPA/WPA2 */
		(*klpe_lbs_enable_rsn)(priv, sme->crypto.cipher_group != 0);
		break;
	default:
		wiphy_err(wiphy, "unsupported cipher group 0x%x\n",
			  sme->crypto.cipher_group);
		ret = -ENOTSUPP;
		goto done;
	}

	ret = klpr_lbs_set_authtype(priv, sme);
	if (ret == -ENOTSUPP) {
		wiphy_err(wiphy, "unsupported authtype 0x%x\n", sme->auth_type);
		goto done;
	}

	(*klpe_lbs_set_radio)(priv, preamble, 1);

	/* Do the actual association */
	ret = klpp_lbs_associate(priv, bss, sme);

 done:
	if (bss)
		(*klpe_cfg80211_put_bss)(wiphy, bss);
	return ret;
}

#define CAPINFO_MASK (~(0xda00))

static void (*klpe_lbs_join_post)(struct lbs_private *priv,
			  struct cfg80211_ibss_params *params,
			  u8 *bssid, u16 capability);

/* patched */
int klpp_lbs_ibss_join_existing(struct lbs_private *priv,
	struct cfg80211_ibss_params *params,
	struct cfg80211_bss *bss)
{
	const u8 *rates_eid;
	struct cmd_ds_802_11_ad_hoc_join cmd;
	u8 preamble = RADIO_PREAMBLE_SHORT;
	int ret = 0;
	/*
	 * Fix CVE-2019-14897
	 *  +3 lines
	 */
	int hw, i;
	u8 rates_max;
	u8 *rates;

	/* TODO: set preamble based on scan result */
	ret = (*klpe_lbs_set_radio)(priv, preamble, 1);
	if (ret)
		goto out;

	/*
	 * Example CMD_802_11_AD_HOC_JOIN command:
	 *
	 * command         2c 00         CMD_802_11_AD_HOC_JOIN
	 * size            65 00
	 * sequence        xx xx
	 * result          00 00
	 * bssid           02 27 27 97 2f 96
	 * ssid            49 42 53 53 00 00 00 00
	 *                 00 00 00 00 00 00 00 00
	 *                 00 00 00 00 00 00 00 00
	 *                 00 00 00 00 00 00 00 00
	 * type            02            CMD_BSS_TYPE_IBSS
	 * beacon period   64 00
	 * dtim period     00
	 * timestamp       00 00 00 00 00 00 00 00
	 * localtime       00 00 00 00 00 00 00 00
	 * IE DS           03
	 * IE DS len       01
	 * IE DS channel   01
	 * reserveed       00 00 00 00
	 * IE IBSS         06
	 * IE IBSS len     02
	 * IE IBSS atim    00 00
	 * reserved        00 00 00 00
	 * capability      02 00
	 * rates           82 84 8b 96 0c 12 18 24 30 48 60 6c 00
	 * fail timeout    ff 00
	 * probe delay     00 00
	 */
	memset(&cmd, 0, sizeof(cmd));
	cmd.hdr.size = cpu_to_le16(sizeof(cmd));

	memcpy(cmd.bss.bssid, bss->bssid, ETH_ALEN);
	memcpy(cmd.bss.ssid, params->ssid, params->ssid_len);
	cmd.bss.type = CMD_BSS_TYPE_IBSS;
	cmd.bss.beaconperiod = cpu_to_le16(params->beacon_interval);
	cmd.bss.ds.header.id = WLAN_EID_DS_PARAMS;
	cmd.bss.ds.header.len = 1;
	cmd.bss.ds.channel = params->chandef.chan->hw_value;
	cmd.bss.ibss.header.id = WLAN_EID_IBSS_PARAMS;
	cmd.bss.ibss.header.len = 2;
	cmd.bss.ibss.atimwindow = 0;
	cmd.bss.capability = cpu_to_le16(bss->capability & CAPINFO_MASK);

	/* set rates to the intersection of our rates and the rates in the
	   bss */
	rcu_read_lock();
	rates_eid = (*klpe_ieee80211_bss_get_ie)(bss, WLAN_EID_SUPP_RATES);
	if (!rates_eid) {
		klpr_lbs_add_rates(cmd.bss.rates);
	} else {
		/*
		 * Fix CVE-2019-14897
		 *  -3 lines, +8 lines
		 */
		rates_max = rates_eid[1];
		if (rates_max > MAX_RATES) {
			lbs_deb_join("invalid rates");
			rcu_read_unlock();
			ret = -EINVAL;
			goto out;
		}
		rates = cmd.bss.rates;
		for (hw = 0; hw < ARRAY_SIZE((*klpe_lbs_rates)); hw++) {
			u8 hw_rate = (*klpe_lbs_rates)[hw].bitrate / 5;
			for (i = 0; i < rates_max; i++) {
				if (hw_rate == (rates_eid[i+2] & 0x7f)) {
					u8 rate = rates_eid[i+2];
					if (rate == 0x02 || rate == 0x04 ||
					    rate == 0x0b || rate == 0x16)
						rate |= 0x80;
					*rates++ = rate;
				}
			}
		}
	}
	rcu_read_unlock();

	/* Only v8 and below support setting this */
	if (MRVL_FW_MAJOR_REV(priv->fwrelease) <= 8) {
		cmd.failtimeout = cpu_to_le16(MRVDRV_ASSOCIATION_TIME_OUT);
		cmd.probedelay = cpu_to_le16(CMD_SCAN_PROBE_DELAY_TIME);
	}
	ret = klpr_lbs_cmd_with_response(priv, CMD_802_11_AD_HOC_JOIN, &cmd);
	if (ret)
		goto out;

	/*
	 * This is a sample response to CMD_802_11_AD_HOC_JOIN:
	 *
	 * response        2c 80
	 * size            09 00
	 * sequence        xx xx
	 * result          00 00
	 * reserved        00
	 */
	(*klpe_lbs_join_post)(priv, params, bss->bssid, bss->capability);

 out:
	return ret;
}


static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "lbs_rates", (void *)&klpe_lbs_rates, "libertas" },
	{ "ieee80211_bss_get_ie", (void *)&klpe_ieee80211_bss_get_ie,
	  "cfg80211" },
	{ "cfg80211_connect_done", (void *)&klpe_cfg80211_connect_done,
	  "cfg80211" },
	{ "cfg80211_get_bss", (void *)&klpe_cfg80211_get_bss, "cfg80211" },
	{ "cfg80211_put_bss", (void *)&klpe_cfg80211_put_bss, "cfg80211" },
	{ "ieee80211_get_num_supported_channels",
	  (void *)&klpe_ieee80211_get_num_supported_channels, "cfg80211" },
	{ "__lbs_cmd", (void *)&klpe___lbs_cmd, "libertas" },
	{ "lbs_cmd_copyback", (void *)&klpe_lbs_cmd_copyback, "libertas" },
	{ "lbs_set_radio", (void *)&klpe_lbs_set_radio, "libertas" },
	{ "lbs_set_mac_control", (void *)&klpe_lbs_set_mac_control,
	  "libertas" },
	{ "lbs_remove_wep_keys", (void *)&klpe_lbs_remove_wep_keys,
	  "libertas" },
	{ "lbs_set_wep_keys", (void *)&klpe_lbs_set_wep_keys, "libertas" },
	{ "lbs_enable_rsn", (void *)&klpe_lbs_enable_rsn, "libertas" },
	{ "lbs_set_key_material", (void *)&klpe_lbs_set_key_material,
	  "libertas" },
	{ "lbs_join_post", (void *)&klpe_lbs_join_post, "libertas" },
};

static int livepatch_bsc1160467_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1160467_module_nb = {
	.notifier_call = livepatch_bsc1160467_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1160467_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1160467_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1160467_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1160467_module_nb);
}

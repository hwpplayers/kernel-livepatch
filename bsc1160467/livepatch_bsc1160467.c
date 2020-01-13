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


static const u8 *(*klpe_ieee80211_bss_get_ie)(struct cfg80211_bss *bss, u8 ie);

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


/* from drivers/net/wireless/marvell/libertas/defs.h */
#define LBS_DEB_CFG80211 0x02000000

#define LBS_DEB_LL(grp, grpnam, fmt, args...) do {} while (0)

#define lbs_deb_assoc(fmt, args...)     LBS_DEB_LL(LBS_DEB_ASSOC, " assoc", fmt, ##args)
#define lbs_deb_join(fmt, args...)      LBS_DEB_LL(LBS_DEB_JOIN, " join", fmt, ##args)

#define lbs_deb_hex(grp,prompt,buf,len)	do {} while (0)

#define MRVDRV_MAX_MULTICAST_LIST_SIZE	32

#define MRVDRV_ASSOCIATION_TIME_OUT	255

#define	LBS_UPLD_SIZE			2312

#define MRVL_FW_MAJOR_REV(x)				((x)>>24)

#define MAX_RATES			14


/* from drivers/net/wireless/marvell/libertas/host.h */
#define CMD_802_11_AD_HOC_JOIN                  0x002c

#define CMD_BSS_TYPE_IBSS                       0x0002

#define CMD_SCAN_PROBE_DELAY_TIME               0

#define RADIO_PREAMBLE_SHORT                    0x02

struct cmd_header {
	__le16 command;
	__le16 size;
	__le16 seqnum;
	__le16 result;
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


/* from drivers/net/wireless/marvell/libertas/cfg.c */
static struct ieee80211_rate (*klpe_lbs_rates)[12];

static int (*klpe_lbs_add_rates)(u8 *rates);

/* patched */
u8 *klpp_add_ie_rates(u8 *tlv, const u8 *ie, int *nrates)
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
		(*klpe_lbs_add_rates)(cmd.bss.rates);
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
	{ "__lbs_cmd", (void *)&klpe___lbs_cmd, "libertas" },
	{ "lbs_cmd_copyback", (void *)&klpe_lbs_cmd_copyback, "libertas" },
	{ "lbs_set_radio", (void *)&klpe_lbs_set_radio, "libertas" },
	{ "lbs_add_rates", (void *)&klpe_lbs_add_rates, "libertas" },
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

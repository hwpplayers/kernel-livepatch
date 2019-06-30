/*
 * livepatch_bsc1136446
 *
 * Fix for CVE-2019-3846, bsc#1136446 + bsc#1136935 (no CVE assigned yet)
 *
 *  Upstream commits:
 *  13ec7f10b87f ("mwifiex: Fix possible buffer overflows at parsing bss
 *                 descriptor")
 *  685c9b7750bf ("mwifiex: Abort at too short BSS descriptor element")
 *  69ae4f6aac15 ("mwifiex: Fix heap overflow in mwifiex_uap_parse_tail_ies()")
 *
 *  SLE12 + SLE12-SP1 commits:
 *  16ea19d2d30836816f073d8390d6a7882ec228ea
 *  4bce39afdb02c60f759e9ef2e48c4e6c6f7e7223
 *
 *  SLE12-SP2 + SLE12-SP3 commits:
 *  a706b0de01247202dcb210cdf0b1a777e015c878
 *  955c6c19171973d7bf21fd8cb567a6ef6c1b50c4
 *  7b3a4bfc129593c3741835e3639b810c96cb27c6
 *
 *  SLE12-SP4 + SLE15 + SLE15-SP1 commits:
 *  ace6d6795e2988d3d83fed5e2b76e3e120a95b25
 *  b07c2e2dfe2fe2b72ed41a3827f734ef5727813d
 *  962016bf8d786529a37616026cc0315d6a876ff4
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/skbuff.h>
#include <linux/idr.h>
#include <linux/workqueue.h>
#include <net/mac80211.h>
#include <net/lib80211.h>
#include "livepatch_bsc1136446.h"
#include "kallsyms_relocs.h"

#if !IS_MODULE(CONFIG_MWIFIEX)
#error "Live patch supports only CONFIG_MWIFIEX=m"
#endif

#define LIVEPATCHED_MODULE "mwifiex"


struct mwifiex_private;
struct mwifiex_ie;
struct mwifiex_adapter;

static
int (*klp_mwifiex_update_uap_custom_ie)(struct mwifiex_private *priv,
					struct mwifiex_ie *beacon_ie,
					u16 *beacon_idx,
					struct mwifiex_ie *pr_ie,
					u16 *probe_idx,
					struct mwifiex_ie *ar_ie,
					u16 *assoc_idx);
static int (*klp_mwifiex_update_vs_ie)(const u8 *ies, int ies_len,
				       struct mwifiex_ie **ie_ptr, u16 mask,
				       unsigned int oui, u8 oui_type);
static void (*klp__mwifiex_dbg)(const struct mwifiex_adapter *adapter, int mask,
				const char *fmt, ...);
static const u8 *(*klp_cfg80211_find_vendor_ie)(unsigned int oui, int oui_type,
						const u8 *ies, int len);

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "mwifiex_update_uap_custom_ie",
	  (void *)&klp_mwifiex_update_uap_custom_ie, "mwifiex" },
	{ "mwifiex_update_vs_ie",
	  (void *)&klp_mwifiex_update_vs_ie, "mwifiex" },
	{ "_mwifiex_dbg", (void *)&klp__mwifiex_dbg, "mwifiex" },
	{ "cfg80211_find_vendor_ie", (void *)&klp_cfg80211_find_vendor_ie,
	  "cfg80211" },
};

/* from drivers/net/wireless/marvell/mwifiex/decl.h */
#define KLP_MWIFIEX_WPA_PASSHPHRASE_LEN 64

struct wpa_param {
	u8 pairwise_cipher_wpa;
	u8 pairwise_cipher_wpa2;
	u8 group_cipher;
	u32 length;
	u8 passphrase[KLP_MWIFIEX_WPA_PASSHPHRASE_LEN];
};

struct wep_key {
	u8 key_index;
	u8 is_default;
	u16 length;
	u8 key[WLAN_KEY_LEN_WEP104];
};

struct mwifiex_802_11_ssid {
	u32 ssid_len;
	u8 ssid[IEEE80211_MAX_SSID_LEN];
};

enum mwifiex_wmm_ac_e {
	WMM_AC_BK,
	WMM_AC_BE,
	WMM_AC_VI,
	WMM_AC_VO
} __packed;

struct ieee_types_wmm_ac_parameters {
	u8 aci_aifsn_bitmap;
	u8 ecw_bitmap;
	__le16 tx_op_limit;
} __packed;

struct mwifiex_types_wmm_info {
	u8 oui[4];
	u8 subtype;
	u8 version;
	u8 qos_info;
	u8 reserved;
	struct ieee_types_wmm_ac_parameters ac_params[IEEE80211_NUM_ACS];
} __packed;

struct mwifiex_11h_intf_state {
	bool is_11h_enabled;
	bool is_11h_active;
} __packed;


/* from drivers/net/wireless/marvell/mwifiex/ioctl.h */
#define KLP_MWIFIEX_SUPPORTED_RATES                 14

struct mwifiex_uap_bss_param {
	u8 channel;
	u8 band_cfg;
	u16 rts_threshold;
	u16 frag_threshold;
	u8 retry_limit;
	struct mwifiex_802_11_ssid ssid;
	u8 bcast_ssid_ctl;
	u8 radio_ctl;
	u8 dtim_period;
	u16 beacon_period;
	u16 auth_mode;
	u16 protocol;
	u16 key_mgmt;
	u16 key_mgmt_operation;
	struct wpa_param wpa_cfg;
	struct wep_key wep_cfg[NUM_WEP_KEYS];
	struct ieee80211_ht_cap ht_cap;
	struct ieee80211_vht_cap vht_cap;
	u8 rates[KLP_MWIFIEX_SUPPORTED_RATES];
	u32 sta_ao_timer;
	u32 ps_sta_ao_timer;
	u8 qos_info;
	u8 power_constraint;
	struct mwifiex_types_wmm_info wmm_info;
};

#define KLP_MAX_NUM_TID     8

#define KLP_PN_LEN				16

struct mwifiex_ds_mem_rw {
	u32 addr;
	u32 value;
};

#define KLP_IEEE_MAX_IE_SIZE		256

struct subsc_evt_cfg {
	u8 abs_value;
	u8 evt_freq;
};

struct mwifiex_ds_misc_subsc_evt {
	u16 action;
	u16 events;
	struct subsc_evt_cfg bcn_l_rssi_cfg;
	struct subsc_evt_cfg bcn_h_rssi_cfg;
};

#define KLP_MWIFIEX_MAX_VSIE_LEN       (256)
#define KLP_MWIFIEX_MAX_VSIE_NUM       (8)


/* from drivers/net/wireless/marvell/mwifiex/fw.h */
#define KLP_WPA_PN_SIZE		8

#define KLP_MWIFIEX_AUTO_IDX_MASK			0xffff

#define KLP_MGMT_MASK_ASSOC_RESP			0x02

#define KLP_MGMT_MASK_REASSOC_RESP			0x08

#define KLP_MGMT_MASK_PROBE_RESP			0x20

#define KLP_MGMT_MASK_BEACON			0x100

struct mwifiex_ie_type_key_param_set {
	__le16 type;
	__le16 length;
	__le16 key_type_id;
	__le16 key_info;
	__le16 key_len;
	u8 key[50];
} __packed;

#define KLP_IGTK_PN_LEN		8

struct mwifiex_wep_param {
	__le16 key_len;
	u8 key[WLAN_KEY_LEN_WEP104];
} __packed;

struct mwifiex_tkip_param {
	u8 pn[KLP_WPA_PN_SIZE];
	__le16 key_len;
	u8 key[WLAN_KEY_LEN_TKIP];
} __packed;

struct mwifiex_aes_param {
	u8 pn[KLP_WPA_PN_SIZE];
	__le16 key_len;
	u8 key[WLAN_KEY_LEN_CCMP];
} __packed;

struct mwifiex_wapi_param {
	u8 pn[KLP_PN_LEN];
	__le16 key_len;
	u8 key[WLAN_KEY_LEN_SMS4];
} __packed;

struct mwifiex_cmac_aes_param {
	u8 ipn[KLP_IGTK_PN_LEN];
	__le16 key_len;
	u8 key[WLAN_KEY_LEN_AES_CMAC];
} __packed;

struct mwifiex_ie_type_key_param_set_v2 {
	__le16 type;
	__le16 len;
	u8 mac_addr[ETH_ALEN];
	u8 key_idx;
	u8 key_type;
	__le16 key_info;
	union {
		struct mwifiex_wep_param wep;
		struct mwifiex_tkip_param tkip;
		struct mwifiex_aes_param aes;
		struct mwifiex_wapi_param wapi;
		struct mwifiex_cmac_aes_param cmac_aes;
	} key_params;
} __packed;

struct host_cmd_ds_802_11_key_material_v2 {
	__le16 action;
	struct mwifiex_ie_type_key_param_set_v2 key_param_set;
} __packed;

struct host_cmd_ds_802_11_key_material {
	__le16 action;
	struct mwifiex_ie_type_key_param_set key_param_set;
} __packed;


struct ieee_types_cf_param_set {
	u8 element_id;
	u8 len;
	u8 cfp_cnt;
	u8 cfp_period;
	__le16 cfp_max_duration;
	__le16 cfp_duration_remaining;
} __packed;

struct ieee_types_ibss_param_set {
	u8 element_id;
	u8 len;
	__le16 atim_window;
} __packed;

union ieee_types_ss_param_set {
	struct ieee_types_cf_param_set cf_param_set;
	struct ieee_types_ibss_param_set ibss_param_set;
} __packed;

struct ieee_types_fh_param_set {
	u8 element_id;
	u8 len;
	__le16 dwell_time;
	u8 hop_set;
	u8 hop_pattern;
	u8 hop_index;
} __packed;

struct ieee_types_ds_param_set {
	u8 element_id;
	u8 len;
	u8 current_chan;
} __packed;

union ieee_types_phy_param_set {
	struct ieee_types_fh_param_set fh_param_set;
	struct ieee_types_ds_param_set ds_param_set;
} __packed;

#define KLP_MWIFIEX_USER_SCAN_CHAN_MAX             50

struct mwifiex_user_scan_chan {
	u8 chan_number;
	u8 radio_type;
	u8 scan_type;
	u8 reserved;
	u32 scan_time;
} __packed;

struct ieee_types_vendor_header {
	u8 element_id;
	u8 len;
	u8 oui[4];	/* 0~2: oui, 3: oui_type */
	u8 oui_subtype;
	u8 version;
} __packed;

struct ieee_types_wmm_parameter {
	/*
	 * WMM Parameter IE - Vendor Specific Header:
	 *   element_id  [221/0xdd]
	 *   Len         [24]
	 *   Oui         [00:50:f2]
	 *   OuiType     [2]
	 *   OuiSubType  [1]
	 *   Version     [1]
	 */
	struct ieee_types_vendor_header vend_hdr;
	u8 qos_info_bitmap;
	u8 reserved;
	struct ieee_types_wmm_ac_parameters ac_params[IEEE80211_NUM_ACS];
} __packed;

struct ieee_types_wmm_info {

	/*
	 * WMM Info IE - Vendor Specific Header:
	 *   element_id  [221/0xdd]
	 *   Len         [7]
	 *   Oui         [00:50:f2]
	 *   OuiType     [2]
	 *   OuiSubType  [0]
	 *   Version     [1]
	 */
	struct ieee_types_vendor_header vend_hdr;

	u8 qos_info_bitmap;
} __packed;

struct mwifiex_wmm_ac_status {
	u8 disabled;
	u8 flow_required;
	u8 flow_created;
};

struct mwifiex_ie {
	__le16 ie_index;
	__le16 mgmt_subtype_mask;
	__le16 ie_length;
	u8 ie_buffer[KLP_IEEE_MAX_IE_SIZE];
} __packed;

#define KLP_MAX_MGMT_IE_INDEX	16


/* from drivers/net/wireless/marvell/mwifiex/main.h */
#define KLP_MWIFIEX_KEY_BUFFER_SIZE			16

#define KLP_MAX_BITMAP_RATES_SIZE			18

enum MWIFIEX_DEBUG_LEVEL {
	MWIFIEX_DBG_MSG		= 0x00000001,
	MWIFIEX_DBG_FATAL	= 0x00000002,
	MWIFIEX_DBG_ERROR	= 0x00000004,
	MWIFIEX_DBG_DATA	= 0x00000008,
	MWIFIEX_DBG_CMD		= 0x00000010,
	MWIFIEX_DBG_EVENT	= 0x00000020,
	MWIFIEX_DBG_INTR	= 0x00000040,
	MWIFIEX_DBG_IOCTL	= 0x00000080,

	MWIFIEX_DBG_MPA_D	= 0x00008000,
	MWIFIEX_DBG_DAT_D	= 0x00010000,
	MWIFIEX_DBG_CMD_D	= 0x00020000,
	MWIFIEX_DBG_EVT_D	= 0x00040000,
	MWIFIEX_DBG_FW_D	= 0x00080000,
	MWIFIEX_DBG_IF_D	= 0x00100000,

	MWIFIEX_DBG_ENTRY	= 0x10000000,
	MWIFIEX_DBG_WARN	= 0x20000000,
	MWIFIEX_DBG_INFO	= 0x40000000,
	MWIFIEX_DBG_DUMP	= 0x80000000,

	MWIFIEX_DBG_ANY		= 0xffffffff
};

/* resolve to _mwifiex_dbg() */
#define klp_mwifiex_dbg(adapter, mask, fmt, ...)			\
	klp__mwifiex_dbg(adapter, MWIFIEX_DBG_##mask, fmt, ##__VA_ARGS__)

struct mwifiex_add_ba_param {
	u32 tx_win_size;
	u32 rx_win_size;
	u32 timeout;
	u8 tx_amsdu;
	u8 rx_amsdu;
};

struct mwifiex_tx_aggr {
	u8 ampdu_user;
	u8 ampdu_ap;
	u8 amsdu;
};

struct mwifiex_tid_tbl {
	struct list_head ra_list;
};

#define KLP_WMM_HIGHEST_PRIORITY		7

struct mwifiex_wmm_desc {
	struct mwifiex_tid_tbl tid_tbl_ptr[KLP_MAX_NUM_TID];
	u32 packets_out[KLP_MAX_NUM_TID];
	u32 pkts_paused[KLP_MAX_NUM_TID];
	/* spin lock to protect ra_list */
	spinlock_t ra_list_spinlock;
	struct mwifiex_wmm_ac_status ac_status[IEEE80211_NUM_ACS];
	enum mwifiex_wmm_ac_e ac_down_graded_vals[IEEE80211_NUM_ACS];
	u32 drv_pkt_delay_max;
	u8 queue_priority[IEEE80211_NUM_ACS];
	u32 user_pri_pkt_tx_ctrl[KLP_WMM_HIGHEST_PRIORITY + 1];	/* UP: 0 to 7 */
	/* Number of transmit packets queued */
	atomic_t tx_pkts_queued;
	/* Tracks highest priority with a packet queued */
	atomic_t highest_queued_prio;
};

struct mwifiex_802_11_security {
	u8 wpa_enabled;
	u8 wpa2_enabled;
	u8 wapi_enabled;
	u8 wapi_key_on;
	u8 wep_enabled;
	u32 authentication_mode;
	u8 is_authtype_auto;
	u32 encryption_mode;
};

struct ieee_types_header {
	u8 element_id;
	u8 len;
} __packed;

struct ieee_types_vendor_specific {
	struct ieee_types_vendor_header vend_hdr;
	u8 data[KLP_IEEE_MAX_IE_SIZE - sizeof(struct ieee_types_vendor_header)];
} __packed;

struct mwifiex_bssdescriptor {
	u8 mac_address[ETH_ALEN];
	struct cfg80211_ssid ssid;
	u32 privacy;
	s32 rssi;
	u32 channel;
	u32 freq;
	u16 beacon_period;
	u8 erp_flags;
	u32 bss_mode;
	u8 supported_rates[KLP_MWIFIEX_SUPPORTED_RATES];
	u8 data_rates[KLP_MWIFIEX_SUPPORTED_RATES];
	/* Network band.
	 * BAND_B(0x01): 'b' band
	 * BAND_G(0x02): 'g' band
	 * BAND_A(0X04): 'a' band
	 */
	u16 bss_band;
	u64 fw_tsf;
	u64 timestamp;
	union ieee_types_phy_param_set phy_param_set;
	union ieee_types_ss_param_set ss_param_set;
	u16 cap_info_bitmap;
	struct ieee_types_wmm_parameter wmm_ie;
	u8  disable_11n;
	struct ieee80211_ht_cap *bcn_ht_cap;
	u16 ht_cap_offset;
	struct ieee80211_ht_operation *bcn_ht_oper;
	u16 ht_info_offset;
	u8 *bcn_bss_co_2040;
	u16 bss_co_2040_offset;
	u8 *bcn_ext_cap;
	u16 ext_cap_offset;
	struct ieee80211_vht_cap *bcn_vht_cap;
	u16 vht_cap_offset;
	struct ieee80211_vht_operation *bcn_vht_oper;
	u16 vht_info_offset;
	struct ieee_types_oper_mode_ntf *oper_mode;
	u16 oper_mode_offset;
	u8 disable_11ac;
	struct ieee_types_vendor_specific *bcn_wpa_ie;
	u16 wpa_offset;
	struct ieee_types_generic *bcn_rsn_ie;
	u16 rsn_offset;
	struct ieee_types_generic *bcn_wapi_ie;
	u16 wapi_offset;
	u8 *beacon_buf;
	u32 beacon_buf_size;
	u8 sensed_11h;
	u8 local_constraint;
	u8 chan_sw_ie_present;
};

struct mwifiex_current_bss_params {
	struct mwifiex_bssdescriptor bss_descriptor;
	u8 wmm_enabled;
	u8 wmm_uapsd_enabled;
	u8 band;
	u32 num_of_rates;
	u8 data_rates[KLP_MWIFIEX_SUPPORTED_RATES];
};

struct mwifiex_wep_key {
	u32 length;
	u32 key_index;
	u32 key_length;
	u8 key_material[KLP_MWIFIEX_KEY_BUFFER_SIZE];
};

struct mwifiex_chan_freq_power {
	u16 channel;
	u32 freq;
	u16 max_tx_power;
	u8 unsupported;
};

struct mwifiex_vendor_spec_cfg_ie {
	u16 mask;
	u16 flag;
	u8 ie[KLP_MWIFIEX_MAX_VSIE_LEN];
};

struct wps {
	u8 session_enable;
};

struct mwifiex_roc_cfg {
	u64 cookie;
	struct ieee80211_channel chan;
};

struct mwifiex_private {
	struct mwifiex_adapter *adapter;
	u8 bss_type;
	u8 bss_role;
	u8 bss_priority;
	u8 bss_num;
	u8 bss_started;
	u8 frame_type;
	u8 curr_addr[ETH_ALEN];
	u8 media_connected;
	u8 port_open;
	u8 usb_port;
	u32 num_tx_timeout;
	/* track consecutive timeout */
	u8 tx_timeout_cnt;
	struct net_device *netdev;
	struct net_device_stats stats;
	u32 curr_pkt_filter;
	u32 bss_mode;
	u32 pkt_tx_ctrl;
	u16 tx_power_level;
	u8 max_tx_power_level;
	u8 min_tx_power_level;
	u32 tx_ant;
	u32 rx_ant;
	u8 tx_rate;
	u8 tx_htinfo;
	u8 rxpd_htinfo;
	u8 rxpd_rate;
	u16 rate_bitmap;
	u16 bitmap_rates[KLP_MAX_BITMAP_RATES_SIZE];
	u32 data_rate;
	u8 is_data_rate_auto;
	u16 bcn_avg_factor;
	u16 data_avg_factor;
	s16 data_rssi_last;
	s16 data_nf_last;
	s16 data_rssi_avg;
	s16 data_nf_avg;
	s16 bcn_rssi_last;
	s16 bcn_nf_last;
	s16 bcn_rssi_avg;
	s16 bcn_nf_avg;
	struct mwifiex_bssdescriptor *attempted_bss_desc;
	struct cfg80211_ssid prev_ssid;
	u8 prev_bssid[ETH_ALEN];
	struct mwifiex_current_bss_params curr_bss_params;
	u16 beacon_period;
	u8 dtim_period;
	u16 listen_interval;
	u16 atim_window;
	u8 adhoc_channel;
	u8 adhoc_is_link_sensed;
	u8 adhoc_state;
	struct mwifiex_802_11_security sec_info;
	struct mwifiex_wep_key wep_key[NUM_WEP_KEYS];
	u16 wep_key_curr_index;
	u8 wpa_ie[256];
	u16 wpa_ie_len;
	u8 wpa_is_gtk_set;
	struct host_cmd_ds_802_11_key_material aes_key;
	struct host_cmd_ds_802_11_key_material_v2 aes_key_v2;
	u8 wapi_ie[256];
	u16 wapi_ie_len;
	u8 *wps_ie;
	u16 wps_ie_len;
	u8 wmm_required;
	u8 wmm_enabled;
	u8 wmm_qosinfo;
	struct mwifiex_wmm_desc wmm;
	atomic_t wmm_tx_pending[IEEE80211_NUM_ACS];
	struct list_head sta_list;
	/* spin lock for associated station/TDLS peers list */
	spinlock_t sta_list_spinlock;
	struct list_head auto_tdls_list;
	/* spin lock for auto TDLS peer list */
	spinlock_t auto_tdls_lock;
	struct list_head tx_ba_stream_tbl_ptr;
	/* spin lock for tx_ba_stream_tbl_ptr queue */
	spinlock_t tx_ba_stream_tbl_lock;
	struct mwifiex_tx_aggr aggr_prio_tbl[KLP_MAX_NUM_TID];
	struct mwifiex_add_ba_param add_ba_param;
	u16 rx_seq[KLP_MAX_NUM_TID];
	u8 tos_to_tid_inv[KLP_MAX_NUM_TID];
	struct list_head rx_reorder_tbl_ptr;
	/* spin lock for rx_reorder_tbl_ptr queue */
	spinlock_t rx_reorder_tbl_lock;
	/* spin lock for Rx packets */
	spinlock_t rx_pkt_lock;

#define KLP_MWIFIEX_ASSOC_RSP_BUF_SIZE  500
	u8 assoc_rsp_buf[KLP_MWIFIEX_ASSOC_RSP_BUF_SIZE];
	u32 assoc_rsp_size;

#define KLP_MWIFIEX_GENIE_BUF_SIZE      256
	u8 gen_ie_buf[KLP_MWIFIEX_GENIE_BUF_SIZE];
	u8 gen_ie_buf_len;

	struct mwifiex_vendor_spec_cfg_ie vs_ie[KLP_MWIFIEX_MAX_VSIE_NUM];

#define KLP_MWIFIEX_ASSOC_TLV_BUF_SIZE  256
	u8 assoc_tlv_buf[KLP_MWIFIEX_ASSOC_TLV_BUF_SIZE];
	u8 assoc_tlv_buf_len;

	u8 *curr_bcn_buf;
	u32 curr_bcn_size;
	/* spin lock for beacon buffer */
	spinlock_t curr_bcn_buf_lock;
	struct wireless_dev wdev;
	struct mwifiex_chan_freq_power cfp;
	u32 versionstrsel;
	char version_str[128];
#ifdef CONFIG_DEBUG_FS
	struct dentry *dfs_dev_dir;
#endif
	u16 current_key_index;
	struct semaphore async_sem;
	struct cfg80211_scan_request *scan_request;
	u8 cfg_bssid[6];
	struct wps wps;
	u8 scan_block;
	s32 cqm_rssi_thold;
	u32 cqm_rssi_hyst;
	u8 subsc_evt_rssi_state;
	struct mwifiex_ds_misc_subsc_evt async_subsc_evt_storage;
	struct mwifiex_ie mgmt_ie[KLP_MAX_MGMT_IE_INDEX];
	u16 beacon_idx;
	u16 proberesp_idx;
	u16 assocresp_idx;
	u16 gen_idx;
	u8 ap_11n_enabled;
	u8 ap_11ac_enabled;
	u32 mgmt_frame_mask;
	struct mwifiex_roc_cfg roc_cfg;
	bool scan_aborting;
	u8 sched_scanning;
	u8 csa_chan;
	unsigned long csa_expire_time;
	u8 del_list_idx;
	bool hs2_enabled;
	struct mwifiex_uap_bss_param bss_cfg;
	struct cfg80211_chan_def bss_chandef;
	struct station_parameters *sta_params;
	struct sk_buff_head tdls_txq;
	u8 check_tdls_tx;
	struct timer_list auto_tdls_timer;
	bool auto_tdls_timer_active;
	struct idr ack_status_frames;
	/* spin lock for ack status */
	spinlock_t ack_status_lock;
	/** rx histogram data */
	struct mwifiex_histogram_data *hist_data;
	struct cfg80211_chan_def dfs_chandef;
	struct workqueue_struct *dfs_cac_workqueue;
	struct delayed_work dfs_cac_work;
	struct timer_list dfs_chan_switch_timer;
	struct workqueue_struct *dfs_chan_sw_workqueue;
	struct delayed_work dfs_chan_sw_work;
	struct cfg80211_beacon_data beacon_after;
	struct mwifiex_11h_intf_state state_11h;
	struct mwifiex_ds_mem_rw mem_rw;
	struct sk_buff_head bypass_txq;
	struct mwifiex_user_scan_chan hidden_chan[KLP_MWIFIEX_USER_SCAN_CHAN_MAX];
	u8 assoc_resp_ht_param;
	bool ht_param_present;
	u8 random_mac[ETH_ALEN];
};


/* from drivers/net/wireless/marvell/mwifiex/ie.c */
/* inlined */
static int
klp_mwifiex_set_mgmt_beacon_data_ies(struct mwifiex_private *priv,
				     struct cfg80211_beacon_data *data)
{
	struct mwifiex_ie *beacon_ie = NULL, *pr_ie = NULL, *ar_ie = NULL;
	u16 beacon_idx = KLP_MWIFIEX_AUTO_IDX_MASK, pr_idx = KLP_MWIFIEX_AUTO_IDX_MASK;
	u16 ar_idx = KLP_MWIFIEX_AUTO_IDX_MASK;
	int ret = 0;

	if (data->beacon_ies && data->beacon_ies_len) {
		klp_mwifiex_update_vs_ie(data->beacon_ies, data->beacon_ies_len,
					 &beacon_ie, KLP_MGMT_MASK_BEACON,
					 WLAN_OUI_MICROSOFT,
					 WLAN_OUI_TYPE_MICROSOFT_WPS);
		klp_mwifiex_update_vs_ie(data->beacon_ies, data->beacon_ies_len,
					 &beacon_ie, KLP_MGMT_MASK_BEACON,
					 WLAN_OUI_WFA, WLAN_OUI_TYPE_WFA_P2P);
	}

	if (data->proberesp_ies && data->proberesp_ies_len) {
		klp_mwifiex_update_vs_ie(data->proberesp_ies,
					 data->proberesp_ies_len, &pr_ie,
					 KLP_MGMT_MASK_PROBE_RESP, WLAN_OUI_MICROSOFT,
					 WLAN_OUI_TYPE_MICROSOFT_WPS);
		klp_mwifiex_update_vs_ie(data->proberesp_ies,
					 data->proberesp_ies_len, &pr_ie,
					 KLP_MGMT_MASK_PROBE_RESP,
					 WLAN_OUI_WFA, WLAN_OUI_TYPE_WFA_P2P);
	}

	if (data->assocresp_ies && data->assocresp_ies_len) {
		klp_mwifiex_update_vs_ie(data->assocresp_ies,
					 data->assocresp_ies_len, &ar_ie,
					 KLP_MGMT_MASK_ASSOC_RESP |
					 KLP_MGMT_MASK_REASSOC_RESP,
					 WLAN_OUI_MICROSOFT,
					 WLAN_OUI_TYPE_MICROSOFT_WPS);
		klp_mwifiex_update_vs_ie(data->assocresp_ies,
					 data->assocresp_ies_len, &ar_ie,
					 KLP_MGMT_MASK_ASSOC_RESP |
					 KLP_MGMT_MASK_REASSOC_RESP, WLAN_OUI_WFA,
					 WLAN_OUI_TYPE_WFA_P2P);
	}

	if (beacon_ie || pr_ie || ar_ie) {
		ret = klp_mwifiex_update_uap_custom_ie(priv, beacon_ie,
						       &beacon_idx, pr_ie,
						       &pr_idx, ar_ie, &ar_idx);
		if (ret)
			goto done;
	}

	priv->beacon_idx = beacon_idx;
	priv->proberesp_idx = pr_idx;
	priv->assocresp_idx = ar_idx;

done:
	kfree(beacon_ie);
	kfree(pr_ie);
	kfree(ar_ie);

	return ret;
}



/* patched, inlined */
static int klp_mwifiex_uap_parse_tail_ies(struct mwifiex_private *priv,
					  struct cfg80211_beacon_data *info)
{
	struct mwifiex_ie *gen_ie;
	struct ieee_types_header *hdr;
	struct ieee80211_vendor_ie *vendorhdr;
	u16 gen_idx = KLP_MWIFIEX_AUTO_IDX_MASK, ie_len = 0;
	int left_len, parsed_len = 0;
	/*
	 * Fix bsc#1136935
	 *  +2 lines
	 */
	unsigned int token_len;
	int err = 0;

       if (!info->tail || !info->tail_len)
		return 0;

	gen_ie = kzalloc(sizeof(*gen_ie), GFP_KERNEL);
	if (!gen_ie)
		return -ENOMEM;

	left_len = info->tail_len;

	/* Many IEs are generated in FW by parsing bss configuration.
	 * Let's not add them here; else we may end up duplicating these IEs
	 */
	while (left_len > sizeof(struct ieee_types_header)) {
		hdr = (void *)(info->tail + parsed_len);
		/*
		 * Fix bsc#1136935
		 *  +6 lines
		 */
		token_len = hdr->len + sizeof(struct ieee_types_header);
		if (token_len > left_len) {
			err = -EINVAL;
			goto out;
		}

		switch (hdr->element_id) {
		case WLAN_EID_SSID:
		case WLAN_EID_SUPP_RATES:
		case WLAN_EID_COUNTRY:
		case WLAN_EID_PWR_CONSTRAINT:
		case WLAN_EID_EXT_SUPP_RATES:
		case WLAN_EID_HT_CAPABILITY:
		case WLAN_EID_HT_OPERATION:
		case WLAN_EID_VHT_CAPABILITY:
		case WLAN_EID_VHT_OPERATION:
		case WLAN_EID_VENDOR_SPECIFIC:
			break;
		default:
			/*
			 * Fix bsc#1136935
			 *  -3 lines, +6 lines
			 */
			if (ie_len + token_len > KLP_IEEE_MAX_IE_SIZE) {
				err = -EINVAL;
				goto out;
			}
			memcpy(gen_ie->ie_buffer + ie_len, hdr, token_len);
			ie_len += token_len;
			break;
		}
		/*
		 * Fix bsc#1136935
		 *  -2 lines, +2 lines
		 */
		left_len -= token_len;
		parsed_len += token_len;
	}

	/* parse only WPA vendor IE from tail, WMM IE is configured by
	 * bss_config command
	 */
	vendorhdr = (void *)klp_cfg80211_find_vendor_ie(WLAN_OUI_MICROSOFT,
							WLAN_OUI_TYPE_MICROSOFT_WPA,
							info->tail, info->tail_len);
	if (vendorhdr) {
		/*
		 * Fix bsc#1136935
		 *  -3 lines, +7 lines
		 */
		token_len = vendorhdr->len + sizeof(struct ieee_types_header);
		if (ie_len + token_len > KLP_IEEE_MAX_IE_SIZE) {
			err = -EINVAL;
			goto out;
		}
		memcpy(gen_ie->ie_buffer + ie_len, vendorhdr, token_len);
		ie_len += token_len;
	}

	if (!ie_len) {
		/*
		 * Fix bsc#1136935
		 *  -2 lines, +1 line
		 */
		goto out;
	}

	gen_ie->ie_index = cpu_to_le16(gen_idx);
	gen_ie->mgmt_subtype_mask = cpu_to_le16(KLP_MGMT_MASK_BEACON |
						KLP_MGMT_MASK_PROBE_RESP |
						KLP_MGMT_MASK_ASSOC_RESP);
	gen_ie->ie_length = cpu_to_le16(ie_len);

	if (klp_mwifiex_update_uap_custom_ie(priv, gen_ie, &gen_idx, NULL, NULL,
					     NULL, NULL)) {
		/*
		 * Fix bsc#1136935
		 *  -2 lines, +2 lines
		 */
		err = -EINVAL;
		goto out;
	}

	priv->gen_idx = gen_idx;


	/*
	 * Fix bsc#1136935
	 *  +1 line
	 */
out:
	kfree(gen_ie);
	/*
	 * Fix bsc#1136935
	 *  -1 line, +1 line
	 */
	return err;
}

/* patched, calls inlined mwifiex_uap_parse_tail_ies() */
int klp_mwifiex_set_mgmt_ies(struct mwifiex_private *priv,
			     struct cfg80211_beacon_data *info)
{
	int ret;

	ret = klp_mwifiex_uap_parse_tail_ies(priv, info);

	if (ret)
		return ret;

	return klp_mwifiex_set_mgmt_beacon_data_ies(priv, info);
}

/* patched */
int klp_mwifiex_update_bss_desc_with_ie(struct mwifiex_adapter *adapter,
					struct mwifiex_bssdescriptor *bss_entry)
{
	int ret = 0;
	u8 element_id;
	struct ieee_types_fh_param_set *fh_param_set;
	struct ieee_types_ds_param_set *ds_param_set;
	struct ieee_types_cf_param_set *cf_param_set;
	struct ieee_types_ibss_param_set *ibss_param_set;
	u8 *current_ptr;
	u8 *rate;
	u8 element_len;
	u16 total_ie_len;
	u8 bytes_to_copy;
	u8 rate_size;
	u8 found_data_rate_ie;
	u32 bytes_left;
	struct ieee_types_vendor_specific *vendor_ie;
	const u8 wpa_oui[4] = { 0x00, 0x50, 0xf2, 0x01 };
	const u8 wmm_oui[4] = { 0x00, 0x50, 0xf2, 0x02 };

	found_data_rate_ie = false;
	rate_size = 0;
	current_ptr = bss_entry->beacon_buf;
	bytes_left = bss_entry->beacon_buf_size;

	/* Process variable IE */
	while (bytes_left >= 2) {
		element_id = *current_ptr;
		element_len = *(current_ptr + 1);
		total_ie_len = element_len + sizeof(struct ieee_types_header);

		if (bytes_left < total_ie_len) {
			klp_mwifiex_dbg(adapter, ERROR,
					"err: InterpretIE: in processing\t"
					"IE, bytes left < IE length\n");
			return -1;
		}
		switch (element_id) {
		case WLAN_EID_SSID:
			/*
			 * Fix CVE-2019-3846
			 *  +2 lines
			 */
			if (element_len > IEEE80211_MAX_SSID_LEN)
				return -EINVAL;
			bss_entry->ssid.ssid_len = element_len;
			memcpy(bss_entry->ssid.ssid, (current_ptr + 2),
			       element_len);
			klp_mwifiex_dbg(adapter, INFO,
					"info: InterpretIE: ssid: %-32s\n",
					bss_entry->ssid.ssid);
			break;

		case WLAN_EID_SUPP_RATES:
			/*
			 * Fix CVE-2019-3846
			 *  +2 lines
			 */
			if (element_len > KLP_MWIFIEX_SUPPORTED_RATES)
				return -EINVAL;
			memcpy(bss_entry->data_rates, current_ptr + 2,
			       element_len);
			memcpy(bss_entry->supported_rates, current_ptr + 2,
			       element_len);
			rate_size = element_len;
			found_data_rate_ie = true;
			break;

		case WLAN_EID_FH_PARAMS:
			/*
			 * Fix CVE-2019-3846
			 *  +2 lines
			 */
			if (element_len + 2 < sizeof(*fh_param_set))
				return -EINVAL;
			fh_param_set =
				(struct ieee_types_fh_param_set *) current_ptr;
			memcpy(&bss_entry->phy_param_set.fh_param_set,
			       fh_param_set,
			       sizeof(struct ieee_types_fh_param_set));
			break;

		case WLAN_EID_DS_PARAMS:
			/*
			 * Fix CVE-2019-3846
			 *  +2 lines
			 */
			if (element_len + 2 < sizeof(*ds_param_set))
				return -EINVAL;
			ds_param_set =
				(struct ieee_types_ds_param_set *) current_ptr;

			bss_entry->channel = ds_param_set->current_chan;

			memcpy(&bss_entry->phy_param_set.ds_param_set,
			       ds_param_set,
			       sizeof(struct ieee_types_ds_param_set));
			break;

		case WLAN_EID_CF_PARAMS:
			/*
			 * Fix CVE-2019-3846
			 *  +2 lines
			 */
			if (element_len + 2 < sizeof(*cf_param_set))
				return -EINVAL;
			cf_param_set =
				(struct ieee_types_cf_param_set *) current_ptr;
			memcpy(&bss_entry->ss_param_set.cf_param_set,
			       cf_param_set,
			       sizeof(struct ieee_types_cf_param_set));
			break;

		case WLAN_EID_IBSS_PARAMS:
			/*
			 * Fix CVE-2019-3846
			 *  +2 lines
			 */
			if (element_len + 2 < sizeof(*ibss_param_set))
				return -EINVAL;
			ibss_param_set =
				(struct ieee_types_ibss_param_set *)
				current_ptr;
			memcpy(&bss_entry->ss_param_set.ibss_param_set,
			       ibss_param_set,
			       sizeof(struct ieee_types_ibss_param_set));
			break;

		case WLAN_EID_ERP_INFO:
			/*
			 * Fix CVE-2019-3846
			 *  +2 lines
			 */
			if (!element_len)
				return -EINVAL;
			bss_entry->erp_flags = *(current_ptr + 2);
			break;

		case WLAN_EID_PWR_CONSTRAINT:
			/*
			 * Fix CVE-2019-3846
			 *  +2 lines
			 */
			if (!element_len)
				return -EINVAL;
			bss_entry->local_constraint = *(current_ptr + 2);
			bss_entry->sensed_11h = true;
			break;

		case WLAN_EID_CHANNEL_SWITCH:
			bss_entry->chan_sw_ie_present = true;
		case WLAN_EID_PWR_CAPABILITY:
		case WLAN_EID_TPC_REPORT:
		case WLAN_EID_QUIET:
			bss_entry->sensed_11h = true;
		    break;

		case WLAN_EID_EXT_SUPP_RATES:
			/*
			 * Only process extended supported rate
			 * if data rate is already found.
			 * Data rate IE should come before
			 * extended supported rate IE
			 */
			if (found_data_rate_ie) {
				if ((element_len + rate_size) >
				    KLP_MWIFIEX_SUPPORTED_RATES)
					bytes_to_copy =
						(KLP_MWIFIEX_SUPPORTED_RATES -
						 rate_size);
				else
					bytes_to_copy = element_len;

				rate = (u8 *) bss_entry->data_rates;
				rate += rate_size;
				memcpy(rate, current_ptr + 2, bytes_to_copy);

				rate = (u8 *) bss_entry->supported_rates;
				rate += rate_size;
				memcpy(rate, current_ptr + 2, bytes_to_copy);
			}
			break;

		case WLAN_EID_VENDOR_SPECIFIC:
			/*
			 * Fix CVE-2019-3846
			 *  +3 lines
			 */
			if (element_len + 2 < sizeof(vendor_ie->vend_hdr))
				return -EINVAL;

			vendor_ie = (struct ieee_types_vendor_specific *)
					current_ptr;

			if (!memcmp
			    (vendor_ie->vend_hdr.oui, wpa_oui,
			     sizeof(wpa_oui))) {
				bss_entry->bcn_wpa_ie =
					(struct ieee_types_vendor_specific *)
					current_ptr;
				bss_entry->wpa_offset = (u16)
					(current_ptr - bss_entry->beacon_buf);
			} else if (!memcmp(vendor_ie->vend_hdr.oui, wmm_oui,
				    sizeof(wmm_oui))) {
				if (total_ie_len ==
				    sizeof(struct ieee_types_wmm_parameter) ||
				    total_ie_len ==
				    sizeof(struct ieee_types_wmm_info))
					/*
					 * Only accept and copy the WMM IE if
					 * it matches the size expected for the
					 * WMM Info IE or the WMM Parameter IE.
					 */
					memcpy((u8 *) &bss_entry->wmm_ie,
					       current_ptr, total_ie_len);
			}
			break;
		case WLAN_EID_RSN:
			bss_entry->bcn_rsn_ie =
				(struct ieee_types_generic *) current_ptr;
			bss_entry->rsn_offset = (u16) (current_ptr -
							bss_entry->beacon_buf);
			break;
		case WLAN_EID_BSS_AC_ACCESS_DELAY:
			bss_entry->bcn_wapi_ie =
				(struct ieee_types_generic *) current_ptr;
			bss_entry->wapi_offset = (u16) (current_ptr -
							bss_entry->beacon_buf);
			break;
		case WLAN_EID_HT_CAPABILITY:
			bss_entry->bcn_ht_cap = (struct ieee80211_ht_cap *)
					(current_ptr +
					sizeof(struct ieee_types_header));
			bss_entry->ht_cap_offset = (u16) (current_ptr +
					sizeof(struct ieee_types_header) -
					bss_entry->beacon_buf);
			break;
		case WLAN_EID_HT_OPERATION:
			bss_entry->bcn_ht_oper =
				(struct ieee80211_ht_operation *)(current_ptr +
					sizeof(struct ieee_types_header));
			bss_entry->ht_info_offset = (u16) (current_ptr +
					sizeof(struct ieee_types_header) -
					bss_entry->beacon_buf);
			break;
		case WLAN_EID_VHT_CAPABILITY:
			bss_entry->disable_11ac = false;
			bss_entry->bcn_vht_cap =
				(void *)(current_ptr +
					 sizeof(struct ieee_types_header));
			bss_entry->vht_cap_offset =
					(u16)((u8 *)bss_entry->bcn_vht_cap -
					      bss_entry->beacon_buf);
			break;
		case WLAN_EID_VHT_OPERATION:
			bss_entry->bcn_vht_oper =
				(void *)(current_ptr +
					 sizeof(struct ieee_types_header));
			bss_entry->vht_info_offset =
					(u16)((u8 *)bss_entry->bcn_vht_oper -
					      bss_entry->beacon_buf);
			break;
		case WLAN_EID_BSS_COEX_2040:
			bss_entry->bcn_bss_co_2040 = current_ptr;
			bss_entry->bss_co_2040_offset =
				(u16) (current_ptr - bss_entry->beacon_buf);
			break;
		case WLAN_EID_EXT_CAPABILITY:
			bss_entry->bcn_ext_cap = current_ptr;
			bss_entry->ext_cap_offset =
				(u16) (current_ptr - bss_entry->beacon_buf);
			break;
		case WLAN_EID_OPMODE_NOTIF:
			bss_entry->oper_mode = (void *)current_ptr;
			bss_entry->oper_mode_offset =
					(u16)((u8 *)bss_entry->oper_mode -
					      bss_entry->beacon_buf);
			break;
		default:
			break;
		}

		current_ptr += element_len + 2;

		/* Need to account for IE ID and IE Len */
		bytes_left -= (element_len + 2);

	}	/* while (bytes_left > 2) */
	return ret;
}



static int livepatch_bsc1136446_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1136446_module_nb = {
	.notifier_call = livepatch_bsc1136446_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1136446_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1136446_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1136446_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1136446_module_nb);
}

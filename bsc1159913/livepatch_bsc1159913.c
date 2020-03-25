/*
 * livepatch_bsc1159913
 *
 * Fix for CVE-2019-5108, bsc#1159913
 *
 *  Upstream commit:
 *  3e493173b784 ("mac80211: Do not send Layer 2 Update frame before
 *                 authorization")
 *
 *  SLE12-SP1 commits:
 *  68f09d43ae6494f4d8ac22eab3ec400e249029b3
 *  52624e360c29b858e3dcbb47590701abc07d64ed
 *
 *  SLE12-SP2 and -SP3 commits:
 *  f5e7d563c3fe7f816512a9de33a3f01f42b5b34f
 *  269de19431720d8595f9eac944b1af4b8a9304f6
 *  bb229374d59fab3d64ff79e9d4f2f30b32aebc50
 *
 *  SLE15, SLE12-SP4, SLE15-SP1 and SLE12-SP5 commits:
 *  31c5f32726744f0dae5346eec7aca72fcd73d2c6
 *  3f6532683369be50c283fd07c43d1aa1754c95ea
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

#if !IS_MODULE(CONFIG_MAC80211)
#error "Live patch supports only CONFIG_MAC80211=m"
#endif

#include <linux/ieee80211.h>
#include <linux/nl80211.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <net/net_namespace.h>
#include <linux/rcupdate.h>
#include <linux/if_ether.h>
#include <net/cfg80211.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/etherdevice.h>
#include <linux/leds.h>
#include <linux/idr.h>
#include <linux/rhashtable.h>
#include <net/mac80211.h>
#include <net/fq.h>
#include <linux/average.h>
#include <linux/bitfield.h>
#include <linux/u64_stats_sync.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1159913.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "mac80211"


/* from include/net/cfg80211.h */
static int (*klpe_cfg80211_check_station_change)(struct wiphy *wiphy,
				  struct station_parameters *params,
				  enum cfg80211_station_type statype);


/* from net/mac80211/key.h */
#define NUM_DEFAULT_KEYS 4
#define NUM_DEFAULT_MGMT_KEYS 2


/* from net/mac80211/sta_info.h */
enum ieee80211_sta_info_flags {
	WLAN_STA_AUTH,
	WLAN_STA_ASSOC,
	WLAN_STA_PS_STA,
	WLAN_STA_AUTHORIZED,
	WLAN_STA_SHORT_PREAMBLE,
	WLAN_STA_WDS,
	WLAN_STA_CLEAR_PS_FILT,
	WLAN_STA_MFP,
	WLAN_STA_BLOCK_BA,
	WLAN_STA_PS_DRIVER,
	WLAN_STA_PSPOLL,
	WLAN_STA_TDLS_PEER,
	WLAN_STA_TDLS_PEER_AUTH,
	WLAN_STA_TDLS_INITIATOR,
	WLAN_STA_TDLS_CHAN_SWITCH,
	WLAN_STA_TDLS_OFF_CHANNEL,
	WLAN_STA_TDLS_WIDER_BW,
	WLAN_STA_UAPSD,
	WLAN_STA_SP,
	WLAN_STA_4ADDR_EVENT,
	WLAN_STA_INSERTED,
	WLAN_STA_RATE_CONTROL,
	WLAN_STA_TOFFSET_KNOWN,
	WLAN_STA_MPSP_OWNER,
	WLAN_STA_MPSP_RECIPIENT,
	WLAN_STA_PS_DELIVER,

	NUM_WLAN_STA_FLAGS,
};

struct sta_ampdu_mlme {
	struct mutex mtx;
	/* rx */
	struct tid_ampdu_rx __rcu *tid_rx[IEEE80211_NUM_TIDS];
	u8 tid_rx_token[IEEE80211_NUM_TIDS];
	unsigned long tid_rx_timer_expired[BITS_TO_LONGS(IEEE80211_NUM_TIDS)];
	unsigned long tid_rx_stop_requested[BITS_TO_LONGS(IEEE80211_NUM_TIDS)];
	unsigned long agg_session_valid[BITS_TO_LONGS(IEEE80211_NUM_TIDS)];
	unsigned long unexpected_agg[BITS_TO_LONGS(IEEE80211_NUM_TIDS)];
	/* tx */
	struct work_struct work;
	struct tid_ampdu_tx __rcu *tid_tx[IEEE80211_NUM_TIDS];
	struct tid_ampdu_tx *tid_start_tx[IEEE80211_NUM_TIDS];
	unsigned long last_addba_req_time[IEEE80211_NUM_TIDS];
	u8 addba_req_num[IEEE80211_NUM_TIDS];
	u8 dialog_token_allocator;
};

struct ewma_signal { unsigned long internal; };

struct ieee80211_sta_rx_stats {
	unsigned long packets;
	unsigned long last_rx;
	unsigned long num_duplicates;
	unsigned long fragments;
	unsigned long dropped;
	int last_signal;
	u8 chains;
	s8 chain_signal_last[IEEE80211_MAX_CHAINS];
	u16 last_rate;
	struct u64_stats_sync syncp;
	u64 bytes;
	u64 msdu[IEEE80211_NUM_TIDS + 1];
};

struct sta_info {
	/* General information, mostly static */
	struct list_head list, free_list;
	struct rcu_head rcu_head;
	struct rhlist_head hash_node;
	u8 addr[ETH_ALEN];
	struct ieee80211_local *local;
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_key __rcu *gtk[NUM_DEFAULT_KEYS + NUM_DEFAULT_MGMT_KEYS];
	struct ieee80211_key __rcu *ptk[NUM_DEFAULT_KEYS];
	u8 ptk_idx;
	struct rate_control_ref *rate_ctrl;
	void *rate_ctrl_priv;
	spinlock_t rate_ctrl_lock;
	spinlock_t lock;

	struct ieee80211_fast_tx __rcu *fast_tx;
	struct ieee80211_fast_rx __rcu *fast_rx;
	struct ieee80211_sta_rx_stats __percpu *pcpu_rx_stats;

#ifdef CONFIG_MAC80211_MESH
	struct mesh_sta *mesh;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct work_struct drv_deliver_wk;

	u16 listen_interval;

	bool dead;
	bool removed;

	bool uploaded;

	enum ieee80211_sta_state sta_state;

	/* use the accessors defined below */
	unsigned long _flags;

	/* STA powersave lock and frame queues */
	spinlock_t ps_lock;
	struct sk_buff_head ps_tx_buf[IEEE80211_NUM_ACS];
	struct sk_buff_head tx_filtered[IEEE80211_NUM_ACS];
	unsigned long driver_buffered_tids;
	unsigned long txq_buffered_tids;

	long last_connected;

	/* Updated from RX path only, no locking requirements */
	struct ieee80211_sta_rx_stats rx_stats;
	struct {
		struct ewma_signal signal;
		struct ewma_signal chain_signal[IEEE80211_MAX_CHAINS];
	} rx_stats_avg;

	/* Plus 1 for non-QoS frames */
	__le16 last_seq_ctrl[IEEE80211_NUM_TIDS + 1];

	/* Updated from TX status path only, no locking requirements */
	struct {
		unsigned long filtered;
		unsigned long retry_failed, retry_count;
		unsigned int lost_packets;
		unsigned long last_tdls_pkt_time;
		u64 msdu_retries[IEEE80211_NUM_TIDS + 1];
		u64 msdu_failed[IEEE80211_NUM_TIDS + 1];
		unsigned long last_ack;
	} status_stats;

	/* Updated from TX path only, no locking requirements */
	struct {
		u64 packets[IEEE80211_NUM_ACS];
		u64 bytes[IEEE80211_NUM_ACS];
		struct ieee80211_tx_rate last_rate;
		u64 msdu[IEEE80211_NUM_TIDS + 1];
	} tx_stats;
	u16 tid_seq[IEEE80211_QOS_CTL_TID_MASK + 1];

	/*
	 * Aggregation information, locked with lock.
	 */
	struct sta_ampdu_mlme ampdu_mlme;
	u8 timer_to_tid[IEEE80211_NUM_TIDS];

#ifdef CONFIG_MAC80211_DEBUGFS
	struct dentry *debugfs_dir;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	enum ieee80211_sta_rx_bandwidth cur_max_bandwidth;

	enum ieee80211_smps_mode known_smps_mode;
	const struct ieee80211_cipher_scheme *cipher_scheme;

	u8 reserved_tid;

	struct cfg80211_chan_def tdls_chandef;

	/* keep last! */
	struct ieee80211_sta sta;
};

static inline int test_sta_flag(struct sta_info *sta,
				enum ieee80211_sta_info_flags flag)
{
	return test_bit(flag, &sta->_flags);
}

static struct sta_info *(*klpe_sta_info_get_bss)(struct ieee80211_sub_if_data *sdata,
				  const u8 *addr);

static struct sta_info *(*klpe_sta_info_alloc)(struct ieee80211_sub_if_data *sdata,
				const u8 *addr, gfp_t gfp);

static void (*klpe_sta_info_free)(struct ieee80211_local *local, struct sta_info *sta);

static int (*klpe_sta_info_insert_rcu)(struct sta_info *sta) __acquires(RCU);

static u8 (*klpe_sta_info_tx_streams)(struct sta_info *sta);


/* from net/mac80211/debug.h */
#define MAC80211_HT_DEBUG 0

#define MAC80211_STA_DEBUG 0

#define _sdata_dbg(print, sdata, fmt, ...)				\
do {									\
	if (print)							\
		pr_debug("%s: " fmt,					\
			 (sdata)->name, ##__VA_ARGS__);			\
} while (0)

#define ht_dbg(sdata, fmt, ...)						\
	_sdata_dbg(MAC80211_HT_DEBUG,					\
		   sdata, fmt, ##__VA_ARGS__)

#define sta_dbg(sdata, fmt, ...)					\
	_sdata_dbg(MAC80211_STA_DEBUG,					\
		   sdata, fmt, ##__VA_ARGS__)


/* from net/mac80211/ieee80211_i.h */
#define IEEE80211_FRAGMENT_MAX 4

struct ieee80211_fragment_entry {
	struct sk_buff_head skb_list;
	unsigned long first_frag_time;
	u16 seq;
	u16 extra_len;
	u16 last_frag;
	u8 rx_queue;
	bool check_sequential_pn; /* needed for CCMP/GCMP */
	u8 last_pn[6]; /* PN of the last fragment if CCMP was used */
};

struct ps_data {
	/* yes, this looks ugly, but guarantees that we can later use
	 * bitmap_empty :)
	 * NB: don't touch this bitmap, use sta_info_{set,clear}_tim_bit */
	u8 tim[sizeof(unsigned long) * BITS_TO_LONGS(IEEE80211_MAX_AID + 1)]
			__aligned(__alignof__(unsigned long));
	struct sk_buff_head bc_buf;
	atomic_t num_sta_ps; /* number of stations in PS mode */
	int dtim_count;
	bool dtim_bc_mc;
};

struct ieee80211_if_ap {
	struct beacon_data __rcu *beacon;
	struct probe_resp __rcu *probe_resp;

	/* to be used after channel switch. */
	struct cfg80211_beacon_data *next_beacon;
	struct list_head vlans; /* write-protected with RTNL and local->mtx */

	struct ps_data ps;
	atomic_t num_mcast_sta; /* number of stations receiving multicast */
	enum ieee80211_smps_mode req_smps, /* requested smps mode */
			 driver_smps_mode; /* smps mode request */

	struct work_struct request_smps_work;
	bool multicast_to_unicast;
};

struct ieee80211_if_wds {
	struct sta_info *sta;
	u8 remote_addr[ETH_ALEN];
};

struct ieee80211_if_vlan {
	struct list_head list; /* write-protected with RTNL and local->mtx */

	/* used for all tx if the VLAN is configured to 4-addr mode */
	struct sta_info __rcu *sta;
	atomic_t num_mcast_sta; /* number of stations receiving multicast */
};

struct mesh_stats {
	__u32 fwded_mcast;		/* Mesh forwarded multicast frames */
	__u32 fwded_unicast;		/* Mesh forwarded unicast frames */
	__u32 fwded_frames;		/* Mesh total forwarded frames */
	__u32 dropped_frames_ttl;	/* Not transmitted since mesh_ttl == 0*/
	__u32 dropped_frames_no_route;	/* Not transmitted, no route found */
	__u32 dropped_frames_congestion;/* Not forwarded due to congestion */
};

struct mesh_preq_queue {
	struct list_head list;
	u8 dst[ETH_ALEN];
	u8 flags;
};

struct ieee80211_sta_tx_tspec {
	/* timestamp of the first packet in the time slice */
	unsigned long time_slice_start;

	u32 admitted_time; /* in usecs, unlike over the air */
	u8 tsid;
	s8 up; /* signed to be able to invalidate with -1 during teardown */

	/* consumed TX time in microseconds in the time slice */
	u32 consumed_tx_time;
	enum {
		TX_TSPEC_ACTION_NONE = 0,
		TX_TSPEC_ACTION_DOWNGRADE,
		TX_TSPEC_ACTION_STOP_DOWNGRADE,
	} action;
	bool downgraded;
};

struct ewma_beacon_signal { unsigned long internal; };

struct ieee80211_if_managed {
	struct timer_list timer;
	struct timer_list conn_mon_timer;
	struct timer_list bcn_mon_timer;
	struct timer_list chswitch_timer;
	struct work_struct monitor_work;
	struct work_struct chswitch_work;
	struct work_struct beacon_connection_loss_work;
	struct work_struct csa_connection_drop_work;

	unsigned long beacon_timeout;
	unsigned long probe_timeout;
	int probe_send_count;
	bool nullfunc_failed;
	bool connection_loss;

	struct cfg80211_bss *associated;
	struct ieee80211_mgd_auth_data *auth_data;
	struct ieee80211_mgd_assoc_data *assoc_data;

	u8 bssid[ETH_ALEN] __aligned(2);

	u16 aid;

	bool powersave; /* powersave requested for this iface */
	bool broken_ap; /* AP is broken -- turn off powersave */
	bool have_beacon;
	u8 dtim_period;
	enum ieee80211_smps_mode req_smps, /* requested smps mode */
				 driver_smps_mode; /* smps mode request */

	struct work_struct request_smps_work;

	unsigned int flags;

	bool csa_waiting_bcn;
	bool csa_ignored_same_chan;

	bool beacon_crc_valid;
	u32 beacon_crc;

	bool status_acked;
	bool status_received;
	__le16 status_fc;

	enum {
		IEEE80211_MFP_DISABLED,
		IEEE80211_MFP_OPTIONAL,
		IEEE80211_MFP_REQUIRED
	} mfp; /* management frame protection */

	/*
	 * Bitmask of enabled u-apsd queues,
	 * IEEE80211_WMM_IE_STA_QOSINFO_AC_BE & co. Needs a new association
	 * to take effect.
	 */
	unsigned int uapsd_queues;

	/*
	 * Maximum number of buffered frames AP can deliver during a
	 * service period, IEEE80211_WMM_IE_STA_QOSINFO_SP_ALL or similar.
	 * Needs a new association to take effect.
	 */
	unsigned int uapsd_max_sp_len;

	int wmm_last_param_set;

	u8 use_4addr;

	s16 p2p_noa_index;

	struct ewma_beacon_signal ave_beacon_signal;

	/*
	 * Number of Beacon frames used in ave_beacon_signal. This can be used
	 * to avoid generating less reliable cqm events that would be based
	 * only on couple of received frames.
	 */
	unsigned int count_beacon_signal;

	/* Number of times beacon loss was invoked. */
	unsigned int beacon_loss_count;

	/*
	 * Last Beacon frame signal strength average (ave_beacon_signal / 16)
	 * that triggered a cqm event. 0 indicates that no event has been
	 * generated for the current association.
	 */
	int last_cqm_event_signal;

	/*
	 * State variables for keeping track of RSSI of the AP currently
	 * connected to and informing driver when RSSI has gone
	 * below/above a certain threshold.
	 */
	int rssi_min_thold, rssi_max_thold;
	int last_ave_beacon_signal;

	struct ieee80211_ht_cap ht_capa; /* configured ht-cap over-rides */
	struct ieee80211_ht_cap ht_capa_mask; /* Valid parts of ht_capa */
	struct ieee80211_vht_cap vht_capa; /* configured VHT overrides */
	struct ieee80211_vht_cap vht_capa_mask; /* Valid parts of vht_capa */

	/* TDLS support */
	u8 tdls_peer[ETH_ALEN] __aligned(2);
	struct delayed_work tdls_peer_del_work;
	struct sk_buff *orig_teardown_skb; /* The original teardown skb */
	struct sk_buff *teardown_skb; /* A copy to send through the AP */
	spinlock_t teardown_lock; /* To lock changing teardown_skb */
	bool tdls_chan_switch_prohibited;
	bool tdls_wider_bw_prohibited;

	/* WMM-AC TSPEC support */
	struct ieee80211_sta_tx_tspec tx_tspec[IEEE80211_NUM_ACS];
	/* Use a separate work struct so that we can do something here
	 * while the sdata->work is flushing the queues, for example.
	 * otherwise, in scenarios where we hardly get any traffic out
	 * on the BE queue, but there's a lot of VO traffic, we might
	 * get stuck in a downgraded situation and flush takes forever.
	 */
	struct delayed_work tx_tspec_wk;
};

struct ieee80211_if_ibss {
	struct timer_list timer;
	struct work_struct csa_connection_drop_work;

	unsigned long last_scan_completed;

	u32 basic_rates;

	bool fixed_bssid;
	bool fixed_channel;
	bool privacy;

	bool control_port;
	bool userspace_handles_dfs;

	u8 bssid[ETH_ALEN] __aligned(2);
	u8 ssid[IEEE80211_MAX_SSID_LEN];
	u8 ssid_len, ie_len;
	u8 *ie;
	struct cfg80211_chan_def chandef;

	unsigned long ibss_join_req;
	/* probe response/beacon for IBSS */
	struct beacon_data __rcu *presp;

	struct ieee80211_ht_cap ht_capa; /* configured ht-cap over-rides */
	struct ieee80211_ht_cap ht_capa_mask; /* Valid parts of ht_capa */

	spinlock_t incomplete_lock;
	struct list_head incomplete_stations;

	enum {
		IEEE80211_IBSS_MLME_SEARCH,
		IEEE80211_IBSS_MLME_JOINED,
	} state;
};

struct ieee80211_if_ocb {
	struct timer_list housekeeping_timer;
	unsigned long wrkq_flags;

	spinlock_t incomplete_lock;
	struct list_head incomplete_stations;

	bool joined;
};

struct ieee80211_if_mesh {
	struct timer_list housekeeping_timer;
	struct timer_list mesh_path_timer;
	struct timer_list mesh_path_root_timer;

	unsigned long wrkq_flags;
	unsigned long mbss_changed;

	u8 mesh_id[IEEE80211_MAX_MESH_ID_LEN];
	size_t mesh_id_len;
	/* Active Path Selection Protocol Identifier */
	u8 mesh_pp_id;
	/* Active Path Selection Metric Identifier */
	u8 mesh_pm_id;
	/* Congestion Control Mode Identifier */
	u8 mesh_cc_id;
	/* Synchronization Protocol Identifier */
	u8 mesh_sp_id;
	/* Authentication Protocol Identifier */
	u8 mesh_auth_id;
	/* Local mesh Sequence Number */
	u32 sn;
	/* Last used PREQ ID */
	u32 preq_id;
	atomic_t mpaths;
	/* Timestamp of last SN update */
	unsigned long last_sn_update;
	/* Time when it's ok to send next PERR */
	unsigned long next_perr;
	/* Timestamp of last PREQ sent */
	unsigned long last_preq;
	struct mesh_rmc *rmc;
	spinlock_t mesh_preq_queue_lock;
	struct mesh_preq_queue preq_queue;
	int preq_queue_len;
	struct mesh_stats mshstats;
	struct mesh_config mshcfg;
	atomic_t estab_plinks;
	u32 mesh_seqnum;
	bool accepting_plinks;
	int num_gates;
	struct beacon_data __rcu *beacon;
	const u8 *ie;
	u8 ie_len;
	enum {
		IEEE80211_MESH_SEC_NONE = 0x0,
		IEEE80211_MESH_SEC_AUTHED = 0x1,
		IEEE80211_MESH_SEC_SECURED = 0x2,
	} security;
	bool user_mpm;
	/* Extensible Synchronization Framework */
	const struct ieee80211_mesh_sync_ops *sync_ops;
	s64 sync_offset_clockdrift_max;
	spinlock_t sync_offset_lock;
	/* mesh power save */
	enum nl80211_mesh_power_mode nonpeer_pm;
	int ps_peers_light_sleep;
	int ps_peers_deep_sleep;
	struct ps_data ps;
	/* Channel Switching Support */
	struct mesh_csa_settings __rcu *csa;
	enum {
		IEEE80211_MESH_CSA_ROLE_NONE,
		IEEE80211_MESH_CSA_ROLE_INIT,
		IEEE80211_MESH_CSA_ROLE_REPEATER,
	} csa_role;
	u8 chsw_ttl;
	u16 pre_value;

	/* offset from skb->data while building IE */
	int meshconf_offset;

	struct mesh_table *mesh_paths;
	struct mesh_table *mpp_paths; /* Store paths for MPP&MAP */
	int mesh_paths_generation;
	int mpp_paths_generation;
};

struct ieee80211_if_mntr {
	u32 flags;
	u8 mu_follow_addr[ETH_ALEN] __aligned(2);

	struct list_head list;
};

struct ieee80211_if_nan {
	struct cfg80211_nan_conf conf;

	/* protects function_inst_ids */
	spinlock_t func_lock;
	struct idr function_inst_ids;
};

struct ieee80211_sub_if_data {
	struct list_head list;

	struct wireless_dev wdev;

	/* keys */
	struct list_head key_list;

	/* count for keys needing tailroom space allocation */
	int crypto_tx_tailroom_needed_cnt;
	int crypto_tx_tailroom_pending_dec;
	struct delayed_work dec_tailroom_needed_wk;

	struct net_device *dev;
	struct ieee80211_local *local;

	unsigned int flags;

	unsigned long state;

	char name[IFNAMSIZ];

	/* Fragment table for host-based reassembly */
	struct ieee80211_fragment_entry	fragments[IEEE80211_FRAGMENT_MAX];
	unsigned int fragment_next;

	/* TID bitmap for NoAck policy */
	u16 noack_map;

	/* bit field of ACM bits (BIT(802.1D tag)) */
	u8 wmm_acm;

	struct ieee80211_key __rcu *keys[NUM_DEFAULT_KEYS + NUM_DEFAULT_MGMT_KEYS];
	struct ieee80211_key __rcu *default_unicast_key;
	struct ieee80211_key __rcu *default_multicast_key;
	struct ieee80211_key __rcu *default_mgmt_key;

	u16 sequence_number;
	__be16 control_port_protocol;
	bool control_port_no_encrypt;
	int encrypt_headroom;

	atomic_t num_tx_queued;
	struct ieee80211_tx_queue_params tx_conf[IEEE80211_NUM_ACS];
	struct mac80211_qos_map __rcu *qos_map;

	struct work_struct csa_finalize_work;
	bool csa_block_tx; /* write-protected by sdata_lock and local->mtx */
	struct cfg80211_chan_def csa_chandef;

	struct list_head assigned_chanctx_list; /* protected by chanctx_mtx */
	struct list_head reserved_chanctx_list; /* protected by chanctx_mtx */

	/* context reservation -- protected with chanctx_mtx */
	struct ieee80211_chanctx *reserved_chanctx;
	struct cfg80211_chan_def reserved_chandef;
	bool reserved_radar_required;
	bool reserved_ready;

	/* used to reconfigure hardware SM PS */
	struct work_struct recalc_smps;

	struct work_struct work;
	struct sk_buff_head skb_queue;

	u8 needed_rx_chains;
	enum ieee80211_smps_mode smps_mode;

	int user_power_level; /* in dBm */
	int ap_power_level; /* in dBm */

	bool radar_required;
	struct delayed_work dfs_cac_timer_work;

	/*
	 * AP this belongs to: self in AP mode and
	 * corresponding AP in VLAN mode, NULL for
	 * all others (might be needed later in IBSS)
	 */
	struct ieee80211_if_ap *bss;

	/* bitmap of allowed (non-MCS) rate indexes for rate control */
	u32 rc_rateidx_mask[NUM_NL80211_BANDS];

	bool rc_has_mcs_mask[NUM_NL80211_BANDS];
	u8  rc_rateidx_mcs_mask[NUM_NL80211_BANDS][IEEE80211_HT_MCS_MASK_LEN];

	bool rc_has_vht_mcs_mask[NUM_NL80211_BANDS];
	u16 rc_rateidx_vht_mcs_mask[NUM_NL80211_BANDS][NL80211_VHT_NSS_MAX];

	union {
		struct ieee80211_if_ap ap;
		struct ieee80211_if_wds wds;
		struct ieee80211_if_vlan vlan;
		struct ieee80211_if_managed mgd;
		struct ieee80211_if_ibss ibss;
		struct ieee80211_if_mesh mesh;
		struct ieee80211_if_ocb ocb;
		struct ieee80211_if_mntr mntr;
		struct ieee80211_if_nan nan;
	} u;

#ifdef CONFIG_MAC80211_DEBUGFS
	struct {
		struct dentry *subdir_stations;
		struct dentry *default_unicast_key;
		struct dentry *default_multicast_key;
		struct dentry *default_mgmt_key;
	} debugfs;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct ieee80211_vif vif;
};

enum queue_stop_reason {
	IEEE80211_QUEUE_STOP_REASON_DRIVER,
	IEEE80211_QUEUE_STOP_REASON_PS,
	IEEE80211_QUEUE_STOP_REASON_CSA,
	IEEE80211_QUEUE_STOP_REASON_AGGREGATION,
	IEEE80211_QUEUE_STOP_REASON_SUSPEND,
	IEEE80211_QUEUE_STOP_REASON_SKB_ADD,
	IEEE80211_QUEUE_STOP_REASON_OFFCHANNEL,
	IEEE80211_QUEUE_STOP_REASON_FLUSH,
	IEEE80211_QUEUE_STOP_REASON_TDLS_TEARDOWN,
	IEEE80211_QUEUE_STOP_REASON_RESERVE_TID,

	IEEE80211_QUEUE_STOP_REASONS,
};

enum mac80211_scan_state {
	SCAN_DECISION,
	SCAN_SET_CHANNEL,
	SCAN_SEND_PROBE,
	SCAN_SUSPEND,
	SCAN_RESUME,
	SCAN_ABORT,
};

struct ieee80211_local {
	/* embed the driver visible part.
	 * don't cast (use the static inlines below), but we keep
	 * it first anyway so they become a no-op */
	struct ieee80211_hw hw;

	struct fq fq;
	struct codel_vars *cvars;
	struct codel_params cparams;

	const struct ieee80211_ops *ops;

	/*
	 * private workqueue to mac80211. mac80211 makes this accessible
	 * via ieee80211_queue_work()
	 */
	struct workqueue_struct *workqueue;

	unsigned long queue_stop_reasons[IEEE80211_MAX_QUEUES];
	int q_stop_reasons[IEEE80211_MAX_QUEUES][IEEE80211_QUEUE_STOP_REASONS];
	/* also used to protect ampdu_ac_queue and amdpu_ac_stop_refcnt */
	spinlock_t queue_stop_reason_lock;

	int open_count;
	int monitors, cooked_mntrs;
	/* number of interfaces with corresponding FIF_ flags */
	int fif_fcsfail, fif_plcpfail, fif_control, fif_other_bss, fif_pspoll,
	    fif_probe_req;
	int probe_req_reg;
	unsigned int filter_flags; /* FIF_* */

	bool wiphy_ciphers_allocated;

	bool use_chanctx;

	/* protects the aggregated multicast list and filter calls */
	spinlock_t filter_lock;

	/* used for uploading changed mc list */
	struct work_struct reconfig_filter;

	/* aggregated multicast list */
	struct netdev_hw_addr_list mc_list;

	bool tim_in_locked_section; /* see ieee80211_beacon_get() */

	/*
	 * suspended is true if we finished all the suspend _and_ we have
	 * not yet come up from resume. This is to be used by mac80211
	 * to ensure driver sanity during suspend and mac80211's own
	 * sanity. It can eventually be used for WoW as well.
	 */
	bool suspended;

	/*
	 * Resuming is true while suspended, but when we're reprogramming the
	 * hardware -- at that time it's allowed to use ieee80211_queue_work()
	 * again even though some other parts of the stack are still suspended
	 * and we still drop received frames to avoid waking the stack.
	 */
	bool resuming;

	/*
	 * quiescing is true during the suspend process _only_ to
	 * ease timer cancelling etc.
	 */
	bool quiescing;

	/* device is started */
	bool started;

	/* device is during a HW reconfig */
	bool in_reconfig;

	/* wowlan is enabled -- don't reconfig on resume */
	bool wowlan;

	struct work_struct radar_detected_work;

	/* number of RX chains the hardware has */
	u8 rx_chains;

	int tx_headroom; /* required headroom for hardware/radiotap */

	/* Tasklet and skb queue to process calls from IRQ mode. All frames
	 * added to skb_queue will be processed, but frames in
	 * skb_queue_unreliable may be dropped if the total length of these
	 * queues increases over the limit. */
	struct tasklet_struct tasklet;
	struct sk_buff_head skb_queue;
	struct sk_buff_head skb_queue_unreliable;

	spinlock_t rx_path_lock;

	/* Station data */
	/*
	 * The mutex only protects the list, hash table and
	 * counter, reads are done with RCU.
	 */
	struct mutex sta_mtx;
	spinlock_t tim_lock;
	unsigned long num_sta;
	struct list_head sta_list;
	struct rhltable sta_hash;
	struct timer_list sta_cleanup;
	int sta_generation;

	struct sk_buff_head pending[IEEE80211_MAX_QUEUES];
	struct tasklet_struct tx_pending_tasklet;

	atomic_t agg_queue_stop[IEEE80211_MAX_QUEUES];

	/* number of interfaces with allmulti RX */
	atomic_t iff_allmultis;

	struct rate_control_ref *rate_ctrl;

	struct crypto_cipher *wep_tx_tfm;
	struct crypto_cipher *wep_rx_tfm;
	u32 wep_iv;

	/* see iface.c */
	struct list_head interfaces;
	struct list_head mon_list; /* only that are IFF_UP && !cooked */
	struct mutex iflist_mtx;

	/*
	 * Key mutex, protects sdata's key_list and sta_info's
	 * key pointers (write access, they're RCU.)
	 */
	struct mutex key_mtx;

	/* mutex for scan and work locking */
	struct mutex mtx;

	/* Scanning and BSS list */
	unsigned long scanning;
	struct cfg80211_ssid scan_ssid;
	struct cfg80211_scan_request *int_scan_req;
	struct cfg80211_scan_request __rcu *scan_req;
	struct ieee80211_scan_request *hw_scan_req;
	struct cfg80211_chan_def scan_chandef;
	enum nl80211_band hw_scan_band;
	int scan_channel_idx;
	int scan_ies_len;
	int hw_scan_ies_bufsize;
	struct cfg80211_scan_info scan_info;

	struct work_struct sched_scan_stopped_work;
	struct ieee80211_sub_if_data __rcu *sched_scan_sdata;
	struct cfg80211_sched_scan_request __rcu *sched_scan_req;
	u8 scan_addr[ETH_ALEN];

	unsigned long leave_oper_channel_time;
	enum mac80211_scan_state next_scan_state;
	struct delayed_work scan_work;
	struct ieee80211_sub_if_data __rcu *scan_sdata;
	/* For backward compatibility only -- do not use */
	struct cfg80211_chan_def _oper_chandef;

	/* Temporary remain-on-channel for off-channel operations */
	struct ieee80211_channel *tmp_channel;

	/* channel contexts */
	struct list_head chanctx_list;
	struct mutex chanctx_mtx;

#ifdef CONFIG_MAC80211_LEDS
	struct led_trigger tx_led, rx_led, assoc_led, radio_led;
	struct led_trigger tpt_led;
	atomic_t tx_led_active, rx_led_active, assoc_led_active;
	atomic_t radio_led_active, tpt_led_active;
	struct tpt_led_trigger *tpt_led_trigger;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_MAC80211_DEBUG_COUNTERS
#error "klp-ccp: non-taken branch"
#else /* CONFIG_MAC80211_DEBUG_COUNTERS */

#endif /* CONFIG_MAC80211_DEBUG_COUNTERS */
	int total_ps_buffered; /* total number of all buffered unicast and
				* multicast packets for power saving stations
				*/

	bool pspolling;
	bool offchannel_ps_enabled;
	/*
	 * PS can only be enabled when we have exactly one managed
	 * interface (and monitors) in PS, this then points there.
	 */
	struct ieee80211_sub_if_data *ps_sdata;
	struct work_struct dynamic_ps_enable_work;
	struct work_struct dynamic_ps_disable_work;
	struct timer_list dynamic_ps_timer;
	struct notifier_block ifa_notifier;
	struct notifier_block ifa6_notifier;

	/*
	 * The dynamic ps timeout configured from user space via WEXT -
	 * this will override whatever chosen by mac80211 internally.
	 */
	int dynamic_ps_forced_timeout;

	int user_power_level; /* in dBm, for all interfaces */

	enum ieee80211_smps_mode smps_mode;

	struct work_struct restart_work;

#ifdef CONFIG_MAC80211_DEBUGFS
	struct local_debugfsdentries {
		struct dentry *rcdir;
		struct dentry *keys;
	} debugfs;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct delayed_work roc_work;
	struct list_head roc_list;
	struct work_struct hw_roc_start, hw_roc_done;
	unsigned long hw_roc_start_time;
	u64 roc_cookie_counter;

	struct idr ack_status_frames;
	spinlock_t ack_status_lock;

	struct ieee80211_sub_if_data __rcu *p2p_sdata;

	/* virtual monitor interface */
	struct ieee80211_sub_if_data __rcu *monitor_sdata;
	struct cfg80211_chan_def monitor_chandef;

	/* extended capabilities provided by mac80211 */
	u8 ext_capa[8];

	/* TDLS channel switch */
	struct work_struct tdls_chsw_work;
	struct sk_buff_head skb_queue_tdls_chsw;
};

static inline struct ieee80211_sub_if_data *
IEEE80211_DEV_TO_SUB_IF(struct net_device *dev)
{
	return netdev_priv(dev);
}

static void (*klpe_ieee80211_vif_inc_num_mcast)(struct ieee80211_sub_if_data *sdata);
static void (*klpe_ieee80211_vif_dec_num_mcast)(struct ieee80211_sub_if_data *sdata);

static void (*klpe___ieee80211_check_fast_rx_iface)(struct ieee80211_sub_if_data *sdata);

static void (*klpe_ieee80211_recalc_ps)(struct ieee80211_local *local);
static void (*klpe_ieee80211_recalc_ps_vif)(struct ieee80211_sub_if_data *sdata);

static void (*klpe_ieee80211_check_fast_rx)(struct sta_info *sta);

static void (*klpe_ieee80211_clear_fast_rx)(struct sta_info *sta);

static void (*klpe_ieee80211_check_fast_xmit)(struct sta_info *sta);

static void (*klpe_ieee80211_clear_fast_xmit)(struct sta_info *sta);

static int (*klpe_ieee80211_send_smps_action)(struct ieee80211_sub_if_data *sdata,
			       enum ieee80211_smps_mode smps, const u8 *da,
			       const u8 *bssid);

static void (*klpe_ieee80211_recalc_min_chandef)(struct ieee80211_sub_if_data *sdata);


/* from net/mac80211/rate.h */
static void (*klpe_rate_control_rate_init)(struct sta_info *sta);


/* from net/mac80211/driver-ops.h */
static __must_check
int (*klpe_drv_sta_state)(struct ieee80211_local *local,
		  struct ieee80211_sub_if_data *sdata,
		  struct sta_info *sta,
		  enum ieee80211_sta_state old_state,
		  enum ieee80211_sta_state new_state);


/* from net/mac80211/cfg.c */
static void (*klpe_ieee80211_send_layer2_update)(struct sta_info *sta);

static int (*klpe_sta_apply_parameters)(struct ieee80211_local *local,
				struct sta_info *sta,
				struct station_parameters *params);

int klpp_ieee80211_add_station(struct wiphy *wiphy, struct net_device *dev,
				 const u8 *mac,
				 struct station_parameters *params)
{
	struct ieee80211_local *local = wiphy_priv(wiphy);
	struct sta_info *sta;
	struct ieee80211_sub_if_data *sdata;
	int err;
	/*
	 * Fix CVE-2019-5108
	 *  -1 line
	 */

	if (params->vlan) {
		sdata = IEEE80211_DEV_TO_SUB_IF(params->vlan);

		if (sdata->vif.type != NL80211_IFTYPE_AP_VLAN &&
		    sdata->vif.type != NL80211_IFTYPE_AP)
			return -EINVAL;
	} else
		sdata = IEEE80211_DEV_TO_SUB_IF(dev);

	if (ether_addr_equal(mac, sdata->vif.addr))
		return -EINVAL;

	if (is_multicast_ether_addr(mac))
		return -EINVAL;

	if (params->sta_flags_set & BIT(NL80211_STA_FLAG_TDLS_PEER) &&
	    sdata->vif.type == NL80211_IFTYPE_STATION &&
	    !sdata->u.mgd.associated)
		return -EINVAL;

	sta = (*klpe_sta_info_alloc)(sdata, mac, GFP_KERNEL);
	if (!sta)
		return -ENOMEM;

	if (params->sta_flags_set & BIT(NL80211_STA_FLAG_TDLS_PEER))
		sta->sta.tdls = true;

	err = (*klpe_sta_apply_parameters)(local, sta, params);
	if (err) {
		(*klpe_sta_info_free)(local, sta);
		return err;
	}

	/*
	 * for TDLS and for unassociated station, rate control should be
	 * initialized only when rates are known and station is marked
	 * authorized/associated
	 */
	if (!test_sta_flag(sta, WLAN_STA_TDLS_PEER) &&
	    test_sta_flag(sta, WLAN_STA_ASSOC))
		(*klpe_rate_control_rate_init)(sta);

	/*
	 * Fix CVE-2019-5108
	 *  -3 lines
	 */
	err = (*klpe_sta_info_insert_rcu)(sta);
	if (err) {
		rcu_read_unlock();
		return err;
	}

	/*
	 * Fix CVE-2019-5108
	 *  -3 lines
	 */
	rcu_read_unlock();

	return 0;
}

int klpp_ieee80211_change_station(struct wiphy *wiphy,
				    struct net_device *dev, const u8 *mac,
				    struct station_parameters *params)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = wiphy_priv(wiphy);
	struct sta_info *sta;
	struct ieee80211_sub_if_data *vlansdata;
	enum cfg80211_station_type statype;
	int err;

	mutex_lock(&local->sta_mtx);

	sta = (*klpe_sta_info_get_bss)(sdata, mac);
	if (!sta) {
		err = -ENOENT;
		goto out_err;
	}

	switch (sdata->vif.type) {
	case NL80211_IFTYPE_MESH_POINT:
		if (sdata->u.mesh.user_mpm)
			statype = CFG80211_STA_MESH_PEER_USER;
		else
			statype = CFG80211_STA_MESH_PEER_KERNEL;
		break;
	case NL80211_IFTYPE_ADHOC:
		statype = CFG80211_STA_IBSS;
		break;
	case NL80211_IFTYPE_STATION:
		if (!test_sta_flag(sta, WLAN_STA_TDLS_PEER)) {
			statype = CFG80211_STA_AP_STA;
			break;
		}
		if (test_sta_flag(sta, WLAN_STA_AUTHORIZED))
			statype = CFG80211_STA_TDLS_PEER_ACTIVE;
		else
			statype = CFG80211_STA_TDLS_PEER_SETUP;
		break;
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_AP_VLAN:
		if (test_sta_flag(sta, WLAN_STA_ASSOC))
			statype = CFG80211_STA_AP_CLIENT;
		else
			statype = CFG80211_STA_AP_CLIENT_UNASSOC;
		break;
	default:
		err = -EOPNOTSUPP;
		goto out_err;
	}

	err = (*klpe_cfg80211_check_station_change)(wiphy, params, statype);
	if (err)
		goto out_err;

	if (params->vlan && params->vlan != sta->sdata->dev) {
		vlansdata = IEEE80211_DEV_TO_SUB_IF(params->vlan);

		if (params->vlan->ieee80211_ptr->use_4addr) {
			if (vlansdata->u.vlan.sta) {
				err = -EBUSY;
				goto out_err;
			}

			rcu_assign_pointer(vlansdata->u.vlan.sta, sta);
			(*klpe___ieee80211_check_fast_rx_iface)(vlansdata);
		}

		if (sta->sdata->vif.type == NL80211_IFTYPE_AP_VLAN &&
		    sta->sdata->u.vlan.sta)
			RCU_INIT_POINTER(sta->sdata->u.vlan.sta, NULL);

		if (test_sta_flag(sta, WLAN_STA_AUTHORIZED))
			(*klpe_ieee80211_vif_dec_num_mcast)(sta->sdata);

		sta->sdata = vlansdata;
		(*klpe_ieee80211_check_fast_xmit)(sta);

		/*
		 * Fix CVE-2019-5108
		 *  -1 line, +1 line
		 */
		if (test_sta_flag(sta, WLAN_STA_AUTHORIZED)) {
			(*klpe_ieee80211_vif_inc_num_mcast)(sta->sdata);

			/*
			 * Fix CVE-2019-5108
			 *  +2 lines
			 */
			(*klpe_ieee80211_send_layer2_update)(sta);
		}
		/*
		 * Fix CVE-2019-5108
		 *  -1 line
		 */
	}

	err = (*klpe_sta_apply_parameters)(local, sta, params);
	if (err)
		goto out_err;

	mutex_unlock(&local->sta_mtx);

	if ((sdata->vif.type == NL80211_IFTYPE_AP ||
	     sdata->vif.type == NL80211_IFTYPE_AP_VLAN) &&
	    sta->known_smps_mode != sta->sdata->bss->req_smps &&
	    test_sta_flag(sta, WLAN_STA_AUTHORIZED) &&
	    (*klpe_sta_info_tx_streams)(sta) != 1) {
		ht_dbg(sta->sdata,
		       "%pM just authorized and MIMO capable - update SMPS\n",
		       sta->sta.addr);
		(*klpe_ieee80211_send_smps_action)(sta->sdata,
			sta->sdata->bss->req_smps,
			sta->sta.addr,
			sta->sdata->vif.bss_conf.bssid);
	}

	if (sdata->vif.type == NL80211_IFTYPE_STATION &&
	    params->sta_flags_mask & BIT(NL80211_STA_FLAG_AUTHORIZED)) {
		(*klpe_ieee80211_recalc_ps)(local);
		(*klpe_ieee80211_recalc_ps_vif)(sdata);
	}

	return 0;
out_err:
	mutex_unlock(&local->sta_mtx);
	return err;
}


/* from net/mac80211/sta_info.c */
static void
(*klpe_ieee80211_recalc_p2p_go_ps_allowed)(struct ieee80211_sub_if_data *sdata);

int klpp_sta_info_move_state(struct sta_info *sta,
			enum ieee80211_sta_state new_state)
{
	might_sleep();

	if (sta->sta_state == new_state)
		return 0;

	/* check allowed transitions first */

	switch (new_state) {
	case IEEE80211_STA_NONE:
		if (sta->sta_state != IEEE80211_STA_AUTH)
			return -EINVAL;
		break;
	case IEEE80211_STA_AUTH:
		if (sta->sta_state != IEEE80211_STA_NONE &&
		    sta->sta_state != IEEE80211_STA_ASSOC)
			return -EINVAL;
		break;
	case IEEE80211_STA_ASSOC:
		if (sta->sta_state != IEEE80211_STA_AUTH &&
		    sta->sta_state != IEEE80211_STA_AUTHORIZED)
			return -EINVAL;
		break;
	case IEEE80211_STA_AUTHORIZED:
		if (sta->sta_state != IEEE80211_STA_ASSOC)
			return -EINVAL;
		break;
	default:
		WARN(1, "invalid state %d", new_state);
		return -EINVAL;
	}

	sta_dbg(sta->sdata, "moving STA %pM to state %d\n",
		sta->sta.addr, new_state);

	/*
	 * notify the driver before the actual changes so it can
	 * fail the transition
	 */
	if (test_sta_flag(sta, WLAN_STA_INSERTED)) {
		int err = (*klpe_drv_sta_state)(sta->local, sta->sdata, sta,
					sta->sta_state, new_state);
		if (err)
			return err;
	}

	/* reflect the change in all state variables */

	switch (new_state) {
	case IEEE80211_STA_NONE:
		if (sta->sta_state == IEEE80211_STA_AUTH)
			clear_bit(WLAN_STA_AUTH, &sta->_flags);
		break;
	case IEEE80211_STA_AUTH:
		if (sta->sta_state == IEEE80211_STA_NONE) {
			set_bit(WLAN_STA_AUTH, &sta->_flags);
		} else if (sta->sta_state == IEEE80211_STA_ASSOC) {
			clear_bit(WLAN_STA_ASSOC, &sta->_flags);
			(*klpe_ieee80211_recalc_min_chandef)(sta->sdata);
			if (!sta->sta.support_p2p_ps)
				(*klpe_ieee80211_recalc_p2p_go_ps_allowed)(sta->sdata);
		}
		break;
	case IEEE80211_STA_ASSOC:
		if (sta->sta_state == IEEE80211_STA_AUTH) {
			set_bit(WLAN_STA_ASSOC, &sta->_flags);
			(*klpe_ieee80211_recalc_min_chandef)(sta->sdata);
			if (!sta->sta.support_p2p_ps)
				(*klpe_ieee80211_recalc_p2p_go_ps_allowed)(sta->sdata);
		} else if (sta->sta_state == IEEE80211_STA_AUTHORIZED) {
			(*klpe_ieee80211_vif_dec_num_mcast)(sta->sdata);
			clear_bit(WLAN_STA_AUTHORIZED, &sta->_flags);
			(*klpe_ieee80211_clear_fast_xmit)(sta);
			(*klpe_ieee80211_clear_fast_rx)(sta);
		}
		break;
	case IEEE80211_STA_AUTHORIZED:
		if (sta->sta_state == IEEE80211_STA_ASSOC) {
			(*klpe_ieee80211_vif_inc_num_mcast)(sta->sdata);
			set_bit(WLAN_STA_AUTHORIZED, &sta->_flags);
			(*klpe_ieee80211_check_fast_xmit)(sta);
			(*klpe_ieee80211_check_fast_rx)(sta);
		}
		/*
		 * Fix CVE-2019-5108
		 *  +3 lines
		 */
		if (sta->sdata->vif.type == NL80211_IFTYPE_AP_VLAN ||
		    sta->sdata->vif.type == NL80211_IFTYPE_AP)
			(*klpe_ieee80211_send_layer2_update)(sta);
		break;
	default:
		break;
	}

	sta->sta_state = new_state;

	return 0;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "cfg80211_check_station_change",
	  (void *)&klpe_cfg80211_check_station_change, "cfg80211" },
	{ "sta_info_get_bss", (void *)&klpe_sta_info_get_bss, "mac80211" },
	{ "sta_info_alloc", (void *)&klpe_sta_info_alloc, "mac80211" },
	{ "sta_info_free", (void *)&klpe_sta_info_free, "mac80211" },
	{ "sta_info_insert_rcu", (void *)&klpe_sta_info_insert_rcu,
	  "mac80211" },
	{ "sta_info_tx_streams", (void *)&klpe_sta_info_tx_streams,
	  "mac80211" },
	{ "ieee80211_vif_dec_num_mcast",
	  (void *)&klpe_ieee80211_vif_dec_num_mcast, "mac80211" },
	{ "ieee80211_vif_inc_num_mcast",
	  (void *)&klpe_ieee80211_vif_inc_num_mcast, "mac80211" },
	{ "__ieee80211_check_fast_rx_iface",
	  (void *)&klpe___ieee80211_check_fast_rx_iface, "mac80211" },
	{ "ieee80211_recalc_ps", (void *)&klpe_ieee80211_recalc_ps,
	  "mac80211" },
	{ "ieee80211_recalc_ps_vif", (void *)&klpe_ieee80211_recalc_ps_vif,
	  "mac80211" },
	{ "ieee80211_send_smps_action",
	  (void *)&klpe_ieee80211_send_smps_action, "mac80211" },
	{ "rate_control_rate_init", (void *)&klpe_rate_control_rate_init,
	  "mac80211" },
	{ "ieee80211_send_layer2_update",
	  (void *)&klpe_ieee80211_send_layer2_update, "mac80211" },
	{ "sta_apply_parameters", (void *)&klpe_sta_apply_parameters,
	  "mac80211" },
	{ "ieee80211_check_fast_rx", (void *)&klpe_ieee80211_check_fast_rx,
	  "mac80211" },
	{ "ieee80211_clear_fast_rx", (void *)&klpe_ieee80211_clear_fast_rx,
	  "mac80211" },
	{ "ieee80211_check_fast_xmit", (void *)&klpe_ieee80211_check_fast_xmit,
	  "mac80211" },
	{ "ieee80211_clear_fast_xmit", (void *)&klpe_ieee80211_clear_fast_xmit,
	  "mac80211" },
	{ "ieee80211_recalc_min_chandef",
	  (void *)&klpe_ieee80211_recalc_min_chandef, "mac80211" },
	{ "drv_sta_state", (void *)&klpe_drv_sta_state, "mac80211" },
	{ "ieee80211_recalc_p2p_go_ps_allowed",
	  (void *)&klpe_ieee80211_recalc_p2p_go_ps_allowed, "mac80211" },
};

static int livepatch_bsc1159913_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1159913_module_nb = {
	.notifier_call = livepatch_bsc1159913_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1159913_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1159913_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1159913_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1159913_module_nb);
}

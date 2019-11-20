/*
 * livepatch_bsc1156317
 *
 * Fix for CVE-2019-15239, bsc#1156317
 *
 *  Upstream commit:
 *  dbbf2d1e4077 ("tcp: reset sk_send_head in tcp_write_queue_purge") from
 *  v4.14 stable tree
 *
 *  SLE12-SP1 commit:
 *  not affected
 *
 *  SLE12-SP2:
 *  not affected
 *
 *  SLE12-SP3 commit:
 *  1878752b301a8f695959376f422b99ec0b991eab
 *
 *  SLE12-SP4, SLE15 and SLE15-SP1 commit:
 *  8e3f3fe43fb3d8cc79e1e739a87a6761155a9d73
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

/* from net/ipv4/tcp_output.c */
#define pr_fmt(fmt) "TCP: " fmt

#include <net/tcp.h>
#include <linux/compiler.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/static_key.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1156317.h"
#include "../kallsyms_relocs.h"


/* from include/net/tcp.h */
static struct sk_buff *(*klpe_sk_stream_alloc_skb)(struct sock *sk, int size, gfp_t gfp,
				    bool force_schedule);

static int (*klpe_sysctl_tcp_timestamps);

static int (*klpe_sysctl_tcp_window_scaling);

static void (*klpe_tcp_clear_retrans)(struct tcp_sock *tp);

int klpp_tcp_connect(struct sock *sk);

static void (*klpe_tcp_finish_connect)(struct sock *sk, struct sk_buff *skb);

static struct tcp_congestion_ops *(*klpe_tcp_ca_find_key)(u32 key);

static bool (*klpe_tcp_fastopen_cookie_check)(struct sock *sk, u16 *mss,
			     struct tcp_fastopen_cookie *cookie);

static void (*klpe_tcp_chrono_start)(struct sock *sk, const enum tcp_chrono type);
static void (*klpe_tcp_chrono_stop)(struct sock *sk, const enum tcp_chrono type);

/* patched */
static inline void klpp_tcp_write_queue_purge(struct sock *sk)
{
	struct sk_buff *skb;

	(*klpe_tcp_chrono_stop)(sk, TCP_CHRONO_BUSY);
	while ((skb = __skb_dequeue(&sk->sk_write_queue)) != NULL)
		sk_wmem_free_skb(sk, skb);
	sk_mem_reclaim(sk);
	tcp_clear_all_retrans_hints(tcp_sk(sk));
	/*
	* Fix CVE-2019-15239
	*  +1 line
	*/
	tcp_init_send_head(sk);
}


/* from net/ipv4/tcp_output.c */
void tcp_select_initial_window(int __space, __u32 mss,
			       __u32 *rcv_wnd, __u32 *window_clamp,
			       int wscale_ok, __u8 *rcv_wscale,
			       __u32 init_rcv_wnd);

static void tcp_ecn_send_syn(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	bool use_ecn = sock_net(sk)->ipv4.sysctl_tcp_ecn == 1 ||
		       tcp_ca_needs_ecn(sk);

	if (!use_ecn) {
		const struct dst_entry *dst = __sk_dst_get(sk);

		if (dst && dst_feature(dst, RTAX_FEATURE_ECN))
			use_ecn = true;
	}

	tp->ecn_flags = 0;

	if (use_ecn) {
		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_ECE | TCPHDR_CWR;
		tp->ecn_flags = TCP_ECN_OK;
		if (tcp_ca_needs_ecn(sk))
			INET_ECN_xmit(sk);
	}
}

static void tcp_init_nondata_skb(struct sk_buff *skb, u32 seq, u8 flags)
{
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum = 0;

	TCP_SKB_CB(skb)->tcp_flags = flags;
	TCP_SKB_CB(skb)->sacked = 0;

	tcp_skb_pcount_set(skb, 1);

	TCP_SKB_CB(skb)->seq = seq;
	if (flags & (TCPHDR_SYN | TCPHDR_FIN))
		seq++;
	TCP_SKB_CB(skb)->end_seq = seq;
}

static int (*klpe___tcp_transmit_skb)(struct sock *sk, struct sk_buff *skb,
			      int clone_it, gfp_t gfp_mask, u32 rcv_nxt);

static int klpr_tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
			    gfp_t gfp_mask)
{
	return (*klpe___tcp_transmit_skb)(sk, skb, clone_it, gfp_mask,
				  tcp_sk(sk)->rcv_nxt);
}

static inline int __tcp_mtu_to_mss(struct sock *sk, int pmtu)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	int mss_now;

	/* Calculate base mss without TCP options:
	   It is MMS_S - sizeof(tcphdr) of rfc1122
	 */
	mss_now = pmtu - icsk->icsk_af_ops->net_header_len - sizeof(struct tcphdr);

	/* IPv6 adds a frag_hdr in case RTAX_FEATURE_ALLFRAG is set */
	if (icsk->icsk_af_ops->net_frag_header_len) {
		const struct dst_entry *dst = __sk_dst_get(sk);

		if (dst && dst_allfrag(dst))
			mss_now -= icsk->icsk_af_ops->net_frag_header_len;
	}

	/* Clamp it (mss_clamp does not include tcp options) */
	if (mss_now > tp->rx_opt.mss_clamp)
		mss_now = tp->rx_opt.mss_clamp;

	/* Now subtract optional transport overhead */
	mss_now -= icsk->icsk_ext_hdr_len;

	/* Then reserve room for full set of TCP options and 8 bytes of data */
	mss_now = max(mss_now, sock_net(sk)->sysctl_tcp_min_snd_mss);
	return mss_now;
}

void tcp_mtup_init(struct sock *sk);

unsigned int tcp_sync_mss(struct sock *sk, u32 pmtu);

static void klpr_tcp_ca_dst_init(struct sock *sk, const struct dst_entry *dst)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcp_congestion_ops *ca;
	u32 ca_key = dst_metric(dst, RTAX_CC_ALGO);

	if (ca_key == TCP_CA_UNSPEC)
		return;

	rcu_read_lock();
	ca = (*klpe_tcp_ca_find_key)(ca_key);
	if (likely(ca && try_module_get(ca->owner))) {
		module_put(icsk->icsk_ca_ops->owner);
		icsk->icsk_ca_dst_locked = tcp_ca_dst_locked(dst);
		icsk->icsk_ca_ops = ca;
	}
	rcu_read_unlock();
}

/* patched, inlined, calls inlined tcp_write_queue_purge() */
static void klpp_tcp_connect_init(struct sock *sk)
{
	const struct dst_entry *dst = __sk_dst_get(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	__u8 rcv_wscale;

	/* We'll fix this up when we get a response from the other end.
	 * See tcp_input.c:tcp_rcv_state_process case TCP_SYN_SENT.
	 */
	tp->tcp_header_len = sizeof(struct tcphdr) +
		((*klpe_sysctl_tcp_timestamps) ? TCPOLEN_TSTAMP_ALIGNED : 0);

#ifdef CONFIG_TCP_MD5SIG
	if (tp->af_specific->md5_lookup(sk, sk))
		tp->tcp_header_len += TCPOLEN_MD5SIG_ALIGNED;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	if (tp->rx_opt.user_mss)
		tp->rx_opt.mss_clamp = tp->rx_opt.user_mss;
	tp->max_window = 0;
	tcp_mtup_init(sk);
	tcp_sync_mss(sk, dst_mtu(dst));

	klpr_tcp_ca_dst_init(sk, dst);

	if (!tp->window_clamp)
		tp->window_clamp = dst_metric(dst, RTAX_WINDOW);
	tp->advmss = tcp_mss_clamp(tp, dst_metric_advmss(dst));

	tcp_initialize_rcv_mss(sk);

	/* limit the window selection if the user enforce a smaller rx buffer */
	if (sk->sk_userlocks & SOCK_RCVBUF_LOCK &&
	    (tp->window_clamp > tcp_full_space(sk) || tp->window_clamp == 0))
		tp->window_clamp = tcp_full_space(sk);

	tcp_select_initial_window(tcp_full_space(sk),
				  tp->advmss - (tp->rx_opt.ts_recent_stamp ? tp->tcp_header_len - sizeof(struct tcphdr) : 0),
				  &tp->rcv_wnd,
				  &tp->window_clamp,
				  (*klpe_sysctl_tcp_window_scaling),
				  &rcv_wscale,
				  dst_metric(dst, RTAX_INITRWND));

	tp->rx_opt.rcv_wscale = rcv_wscale;
	tp->rcv_ssthresh = tp->rcv_wnd;

	sk->sk_err = 0;
	sock_reset_flag(sk, SOCK_DONE);
	tp->snd_wnd = 0;
	tcp_init_wl(tp, 0);
	klpp_tcp_write_queue_purge(sk);
	tp->snd_una = tp->write_seq;
	tp->snd_sml = tp->write_seq;
	tp->snd_up = tp->write_seq;
	tp->snd_nxt = tp->write_seq;

	if (likely(!tp->repair))
		tp->rcv_nxt = 0;
	else
		tp->rcv_tstamp = tcp_jiffies32;
	tp->rcv_wup = tp->rcv_nxt;
	tp->copied_seq = tp->rcv_nxt;

	inet_csk(sk)->icsk_rto = TCP_TIMEOUT_INIT;
	inet_csk(sk)->icsk_retransmits = 0;
	(*klpe_tcp_clear_retrans)(tp);
}

static void (*klpe_tcp_connect_queue_skb)(struct sock *sk, struct sk_buff *skb);

static int klpr_tcp_send_syn_data(struct sock *sk, struct sk_buff *syn)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_fastopen_request *fo = tp->fastopen_req;
	int space, err = 0;
	struct sk_buff *syn_data;

	tp->rx_opt.mss_clamp = tp->advmss;  /* If MSS is not cached */
	if (!(*klpe_tcp_fastopen_cookie_check)(sk, &tp->rx_opt.mss_clamp, &fo->cookie))
		goto fallback;

	/* MSS for SYN-data is based on cached MSS and bounded by PMTU and
	 * user-MSS. Reserve maximum option space for middleboxes that add
	 * private TCP options. The cost is reduced data space in SYN :(
	 */
	tp->rx_opt.mss_clamp = tcp_mss_clamp(tp, tp->rx_opt.mss_clamp);

	space = __tcp_mtu_to_mss(sk, inet_csk(sk)->icsk_pmtu_cookie) -
		MAX_TCP_OPTION_SPACE;

	space = min_t(size_t, space, fo->size);

	/* limit to order-0 allocations */
	space = min_t(size_t, space, SKB_MAX_HEAD(MAX_TCP_HEADER));

	syn_data = (*klpe_sk_stream_alloc_skb)(sk, space, sk->sk_allocation, false);
	if (!syn_data)
		goto fallback;
	syn_data->ip_summed = CHECKSUM_PARTIAL;
	memcpy(syn_data->cb, syn->cb, sizeof(syn->cb));
	if (space) {
		int copied = copy_from_iter(skb_put(syn_data, space), space,
					    &fo->data->msg_iter);
		if (unlikely(!copied)) {
			kfree_skb(syn_data);
			goto fallback;
		}
		if (copied != space) {
			skb_trim(syn_data, copied);
			space = copied;
		}
	}
	/* No more data pending in inet_wait_for_connect() */
	if (space == fo->size)
		fo->data = NULL;
	fo->copied = space;

	(*klpe_tcp_connect_queue_skb)(sk, syn_data);
	if (syn_data->len)
		(*klpe_tcp_chrono_start)(sk, TCP_CHRONO_BUSY);

	err = klpr_tcp_transmit_skb(sk, syn_data, 1, sk->sk_allocation);

	syn->skb_mstamp = syn_data->skb_mstamp;

	/* Now full SYN+DATA was cloned and sent (or not),
	 * remove the SYN from the original skb (syn_data)
	 * we keep in write queue in case of a retransmit, as we
	 * also have the SYN packet (with no data) in the same queue.
	 */
	TCP_SKB_CB(syn_data)->seq++;
	TCP_SKB_CB(syn_data)->tcp_flags = TCPHDR_ACK | TCPHDR_PSH;
	if (!err) {
		tp->syn_data = (fo->copied > 0);
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPORIGDATASENT);
		goto done;
	}

	/* data was not sent, this is our new send_head */
	sk->sk_send_head = syn_data;
	tp->packets_out -= tcp_skb_pcount(syn_data);

fallback:
	/* Send a regular SYN with Fast Open cookie request option */
	if (fo->cookie.len > 0)
		fo->cookie.len = 0;
	err = klpr_tcp_transmit_skb(sk, syn, 1, sk->sk_allocation);
	if (err)
		tp->syn_fastopen = 0;
done:
	fo->cookie.len = -1;  /* Exclude Fast Open option for SYN retries */
	return err;
}

/* patched, calls inlined tcp_connect_init() */
int klpp_tcp_connect(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int err;

	if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
		return -EHOSTUNREACH; /* Routing failure or similar. */

	klpp_tcp_connect_init(sk);

	if (unlikely(tp->repair)) {
		(*klpe_tcp_finish_connect)(sk, NULL);
		return 0;
	}

	buff = (*klpe_sk_stream_alloc_skb)(sk, 0, sk->sk_allocation, true);
	if (unlikely(!buff))
		return -ENOBUFS;

	tcp_init_nondata_skb(buff, tp->write_seq++, TCPHDR_SYN);
	tcp_mstamp_refresh(tp);
	tp->retrans_stamp = tcp_time_stamp(tp);
	(*klpe_tcp_connect_queue_skb)(sk, buff);
	tcp_ecn_send_syn(sk, buff);

	/* Send off SYN; include data in Fast Open. */
	err = tp->fastopen_req ? klpr_tcp_send_syn_data(sk, buff) :
	      klpr_tcp_transmit_skb(sk, buff, 1, sk->sk_allocation);
	if (err == -ECONNREFUSED)
		return err;

	/* We change tp->snd_nxt after the tcp_transmit_skb() call
	 * in order to make this packet get counted in tcpOutSegs.
	 */
	tp->snd_nxt = tp->write_seq;
	tp->pushed_seq = tp->write_seq;
	buff = tcp_send_head(sk);
	if (unlikely(buff)) {
		tp->snd_nxt	= TCP_SKB_CB(buff)->seq;
		tp->pushed_seq	= TCP_SKB_CB(buff)->seq;
	}
	TCP_INC_STATS(sock_net(sk), TCP_MIB_ACTIVEOPENS);

	/* Timer for repeating the SYN until an answer. */
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
				  inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
	return 0;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sk_stream_alloc_skb", (void *)&klpe_sk_stream_alloc_skb },
	{ "sysctl_tcp_timestamps", (void *)&klpe_sysctl_tcp_timestamps },
	{ "sysctl_tcp_window_scaling",
	  (void *)&klpe_sysctl_tcp_window_scaling },
	{ "tcp_clear_retrans", (void *)&klpe_tcp_clear_retrans },
	{ "tcp_finish_connect", (void *)&klpe_tcp_finish_connect },
	{ "tcp_ca_find_key", (void *)&klpe_tcp_ca_find_key },
	{ "tcp_fastopen_cookie_check",
	  (void *)&klpe_tcp_fastopen_cookie_check },
	{ "tcp_chrono_start", (void *)&klpe_tcp_chrono_start },
	{ "tcp_chrono_stop", (void *)&klpe_tcp_chrono_stop },
	{ "__tcp_transmit_skb", (void *)&klpe___tcp_transmit_skb },
	{ "tcp_connect_queue_skb", (void *)&klpe_tcp_connect_queue_skb },
};

int livepatch_bsc1156317_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

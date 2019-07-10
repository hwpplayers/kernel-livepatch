/*
 * livepatch_bsc1137597
 *
 * Fix for CVE-2019-11477 + CVE-2019-11478, bsc#1137597
 *
 *  Upstream commits:
 *  3b4929f65b0d ("tcp: limit payload size of sacked skbs")
 *  f070ef2ac667 ("tcp: tcp_fragment() should apply sane memory limits")
 *  (5f3e2bf008c2 ("tcp: add tcp_min_snd_mss sysctl"))
 *  (967c05aee439 ("tcp: enforce tcp_min_snd_mss in tcp_mtu_probing()"))
 *  stable-4.4.y commit 46c7b5d6f2a5 ("tcp: refine memory limit test in
 *                                     tcp_fragment()")
 *
 *  SLE12 + SLE12-SP1 commits:
 *  6f7ff168995b78101a93865bf562a91273d7435a
 *  80e84be6e13ea67f918571f28177d814e0b7e083
 *  db4f293a17a1ad19e39f2cb1917c8f756a5ebc4b
 *  (48e5a63bc78efdec3cd06c93cbe6cbbb9c0c570d)
 *  (d061d4d128de534400f62e0c175df243da34bc73)
 *  ea193359ae56c672ea973f0066243fbdfa43d734
 *  c9064e0f8aa0d0a372c262790a14b82f013de362
 *
 *  SLE12-SP2 + SLE12-SP3 commits:
 *  b63d7f9a591a47e2ecb8fcd36e2cc2d068be91f8
 *  02ae87c52aeb1f897503b8818c303ba84f6ffb8b
 *  804f0d13b0fa000cba4f7bcd38a3ec2939fcab95
 *  (f8cb4fda4d624c008bb87532bc42290d29046d29)
 *  (f03f5a0ea96c990dbb37114bb0c5b7500c76396c)
 *  (c2f7307376fc535ca83476a24d9662323ad56567)
 *  d10d22d3702ddd19a3ce43260a61659919e89fce
 *  a0d7e38df8ec1b2ba672f43ba14000102ae875eb
 *
 *  SLE12-SP4 + SLE15 + SLE15-SP1 commits:
 *  a7efdcda37c66e80dd2f57d30b40b26200c9e70b
 *  b7da87ac247c6944214da1fd692e72c0ddfa16e9
 *  11077b0f1df9cdfa886d60a90e6c00cf5de0b21b
 *  (67d6de1adfe9b3d12601b799233c311a10fc97a2)
 *  (bd421bec7a1f519f6f50fd56dcc7ef0bf4618886)
 *  (0a0be125c7a1d396ab78e3b3a66d829320d5aa48)
 *  4a006b25335fa286c6ee433d8c176aa5cd67b3fe
 *  18fef7f39b297fc9b860faccf59fad6e0e7e0fb4
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
#include <net/sock.h>
#include <net/tcp.h>
#include "livepatch_bsc1137597.h"
#include "kallsyms_relocs.h"


struct tcp_sacktag_state;

static int (*klp_sysctl_tcp_retrans_collapse);

static u8 (*klp_tcp_sacktag_one)(struct sock *sk,
				 struct tcp_sacktag_state *state, u8 sacked,
				 u32 start_seq, u32 end_seq,
				 int dup_sack, int pcount,
				 u64 xmit_time);
static void (*klp_tcp_rate_skb_delivered)(struct sock *sk, struct sk_buff *skb,
					  struct rate_sample *rs);
static void (*klp_tcp_skb_collapse_tstamp)(struct sk_buff *skb,
					   const struct sk_buff *next_skb);
static int (*klp_skb_shift)(struct sk_buff *tgt, struct sk_buff *skb,
			    int shiftlen);
static int (*klp_tcp_match_skb_to_sack)(struct sock *sk, struct sk_buff *skb,
					u32 start_seq, u32 end_seq);
static struct sk_buff *(*klp_sk_stream_alloc_skb)(struct sock *sk, int size,
						  gfp_t gfp,
						  bool force_schedule);
static void (*klp_tcp_fragment_tstamp)(struct sk_buff *skb,
				       struct sk_buff *skb2);
static void (*klp_tcp_adjust_pcount)(struct sock *sk, const struct sk_buff *skb,
				     int decr);
static int (*klp_tcp_trim_head)(struct sock *sk, struct sk_buff *skb, u32 len);
static unsigned int (*klp_tcp_current_mss)(struct sock *sk);
static int (*klp__tcp_transmit_skb)(struct sock *sk, struct sk_buff *skb,
				    int clone_it, gfp_t gfp_mask, u32 rcv_nxt);

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sysctl_tcp_retrans_collapse",
	  (void *)&klp_sysctl_tcp_retrans_collapse },
	{ "tcp_sacktag_one", (void *)&klp_tcp_sacktag_one },
	{ "tcp_rate_skb_delivered", (void *)&klp_tcp_rate_skb_delivered },
	{ "tcp_skb_collapse_tstamp", (void *)&klp_tcp_skb_collapse_tstamp },
	{ "skb_shift", (void *)&klp_skb_shift },
	{ "tcp_match_skb_to_sack", (void *)&klp_tcp_match_skb_to_sack },
	{ "sk_stream_alloc_skb", (void *)&klp_sk_stream_alloc_skb },
	{ "tcp_fragment_tstamp", (void *)&klp_tcp_fragment_tstamp },
	{ "tcp_adjust_pcount", (void *)&klp_tcp_adjust_pcount },
	{ "tcp_trim_head", (void *)&klp_tcp_trim_head },
	{ "tcp_current_mss", (void *)&klp_tcp_current_mss },
	{ "__tcp_transmit_skb", (void *)&klp__tcp_transmit_skb },
};


/* from net/ipv4/tcp_input.c */
struct tcp_sacktag_state {
	int	reord;
	int	fack_count;
	/* Timestamps for earliest and latest never-retransmitted segment
	 * that was SACKed. RTO needs the earliest RTT to stay conservative,
	 * but congestion control should still get an accurate delay signal.
	 */
	u64	first_sackt;
	u64	last_sackt;
	struct rate_sample *rate;
	int	flag;
};

/* inlined */
static int klp_tcp_skb_seglen(const struct sk_buff *skb)
{
	return tcp_skb_pcount(skb) == 1 ? skb->len : tcp_skb_mss(skb);
}

/* inlined */
static int klp_skb_can_shift(const struct sk_buff *skb)
{
	return !skb_headlen(skb) && skb_is_nonlinear(skb);
}


/* from net/ipv4/tcp_output.c */
/* inlined */
static void klp_tcp_ecn_clear_syn(struct sock *sk, struct sk_buff *skb)
{
	if (sock_net(sk)->ipv4.sysctl_tcp_ecn_fallback)
		/* tp->ecn_flags are cleared at a later point in time when
		 * SYN ACK is ultimatively being received.
		 */
		TCP_SKB_CB(skb)->tcp_flags &= ~(TCPHDR_ECE | TCPHDR_CWR);
}

/* inlined */
static int klp_tcp_transmit_skb(struct sock *sk, struct sk_buff *skb,
				int clone_it, gfp_t gfp_mask)
{
	return klp__tcp_transmit_skb(sk, skb, clone_it, gfp_mask,
				     tcp_sk(sk)->rcv_nxt);
}

/* inlined */
static void klp_tcp_set_skb_tso_segs(struct sk_buff *skb, unsigned int mss_now)
{
	if (skb->len <= mss_now || skb->ip_summed == CHECKSUM_NONE) {
		/* Avoid the costly divide in the normal
		 * non-TSO case.
		 */
		tcp_skb_pcount_set(skb, 1);
		TCP_SKB_CB(skb)->tcp_gso_size = 0;
	} else {
		tcp_skb_pcount_set(skb, DIV_ROUND_UP(skb->len, mss_now));
		TCP_SKB_CB(skb)->tcp_gso_size = mss_now;
	}
}

/* inlined */
static void klp_tcp_skb_fragment_eor(struct sk_buff *skb, struct sk_buff *skb2)
{
	TCP_SKB_CB(skb2)->eor = TCP_SKB_CB(skb)->eor;
	TCP_SKB_CB(skb)->eor = 0;
}

/* inlined on x86_64 */
static bool klp_skb_still_in_host_queue(const struct sock *sk,
					const struct sk_buff *skb)
{
	if (unlikely(skb_fclone_busy(sk, skb))) {
		NET_INC_STATS(sock_net(sk),
			      LINUX_MIB_TCPSPURIOUS_RTX_HOSTQUEUES);
		return true;
	}
	return false;
}

/* inlined */
static bool klp_tcp_can_collapse(const struct sock *sk,
				 const struct sk_buff *skb)
{
	if (tcp_skb_pcount(skb) > 1)
		return false;
	if (skb_cloned(skb))
		return false;
	if (skb == tcp_send_head(sk))
		return false;
	/* Some heuristics for collapsing over SACK'd could be invented */
	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
		return false;

	return true;
}



/* New */
#define KLP_TCP_MIN_SND_MSS			48
#define KLP_TCP_MIN_GSO_SIZE	(KLP_TCP_MIN_SND_MSS - MAX_TCP_OPTION_SPACE)

/* patched, not inlined, but only caller, tcp_shifted_skb_data() also patched */
static bool klp_tcp_shifted_skb(struct sock *sk, struct sk_buff *skb,
				struct tcp_sacktag_state *state,
				unsigned int pcount, int shifted, int mss,
				bool dup_sack)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *prev = tcp_write_queue_prev(sk, skb);
	u32 start_seq = TCP_SKB_CB(skb)->seq;	/* start of newly-SACKed */
	u32 end_seq = start_seq + shifted;	/* end of newly-SACKed */

	BUG_ON(!pcount);

	/* Adjust counters and hints for the newly sacked sequence
	 * range but discard the return value since prev is already
	 * marked. We must tag the range first because the seq
	 * advancement below implicitly advances
	 * tcp_highest_sack_seq() when skb is highest_sack.
	 */
	klp_tcp_sacktag_one(sk, state, TCP_SKB_CB(skb)->sacked,
			    start_seq, end_seq, dup_sack, pcount,
			    skb->skb_mstamp);
	klp_tcp_rate_skb_delivered(sk, skb, state->rate);

	if (skb == tp->lost_skb_hint)
		tp->lost_cnt_hint += pcount;

	TCP_SKB_CB(prev)->end_seq += shifted;
	TCP_SKB_CB(skb)->seq += shifted;

	tcp_skb_pcount_add(prev, pcount);
	/*
	 * Fix CVE-2019-11477
	 *  -1 line, +1 line
	 */
	WARN_ON_ONCE(tcp_skb_pcount(skb) < pcount);
	tcp_skb_pcount_add(skb, -pcount);

	/* When we're adding to gso_segs == 1, gso_size will be zero,
	 * in theory this shouldn't be necessary but as long as DSACK
	 * code can come after this skb later on it's better to keep
	 * setting gso_size to something.
	 */
	if (!TCP_SKB_CB(prev)->tcp_gso_size)
		TCP_SKB_CB(prev)->tcp_gso_size = mss;

	/* CHECKME: To clear or not to clear? Mimics normal skb currently */
	if (tcp_skb_pcount(skb) <= 1)
		TCP_SKB_CB(skb)->tcp_gso_size = 0;

	/* Difference in this won't matter, both ACKed by the same cumul. ACK */
	TCP_SKB_CB(prev)->sacked |= (TCP_SKB_CB(skb)->sacked & TCPCB_EVER_RETRANS);

	if (skb->len > 0) {
		BUG_ON(!tcp_skb_pcount(skb));
		NET_INC_STATS(sock_net(sk), LINUX_MIB_SACKSHIFTED);
		return false;
	}

	/* Whole SKB was eaten :-) */

	if (skb == tp->retransmit_skb_hint)
		tp->retransmit_skb_hint = prev;
	if (skb == tp->lost_skb_hint) {
		tp->lost_skb_hint = prev;
		tp->lost_cnt_hint -= tcp_skb_pcount(prev);
	}

	TCP_SKB_CB(prev)->tcp_flags |= TCP_SKB_CB(skb)->tcp_flags;
	TCP_SKB_CB(prev)->eor = TCP_SKB_CB(skb)->eor;
	if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
		TCP_SKB_CB(prev)->end_seq++;

	if (skb == tcp_highest_sack(sk))
		tcp_advance_highest_sack(sk, skb);

	klp_tcp_skb_collapse_tstamp(prev, skb);
	if (unlikely(TCP_SKB_CB(prev)->tx.delivered_mstamp))
		TCP_SKB_CB(prev)->tx.delivered_mstamp = 0;

	tcp_unlink_write_queue(skb, sk);
	sk_wmem_free_skb(sk, skb);

	NET_INC_STATS(sock_net(sk), LINUX_MIB_SACKMERGED);

	return true;
}

/* New */
static int klp_tcp_skb_shift(struct sk_buff *to, struct sk_buff *from,
			     int pcount, int shiftlen)
{
	/* TCP min gso_size is 8 bytes (TCP_MIN_GSO_SIZE)
	 * Since TCP_SKB_CB(skb)->tcp_gso_segs is 16 bits, we need
	 * to make sure not storing more than 65535 * 8 bytes per skb,
	 * even if current MSS is bigger.
	 */
	if (unlikely(to->len + shiftlen >= 65535 * KLP_TCP_MIN_GSO_SIZE))
		return 0;
	if (unlikely(tcp_skb_pcount(to) + pcount > 65535))
		return 0;
	return klp_skb_shift(to, from, shiftlen);
}

/* patched, inlined */
static struct sk_buff *
klp_tcp_shift_skb_data(struct sock *sk, struct sk_buff *skb,
		       struct tcp_sacktag_state *state,
		       u32 start_seq, u32 end_seq,
		       bool dup_sack)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *prev;
	int mss;
	/*
	 * Fix CVE-2019-11477
	 *  +1 line
	 */
	int next_pcount;
	int pcount = 0;
	int len;
	int in_sack;

	if (!sk_can_gso(sk))
		goto fallback;

	/* Normally R but no L won't result in plain S */
	if (!dup_sack &&
	    (TCP_SKB_CB(skb)->sacked & (TCPCB_LOST|TCPCB_SACKED_RETRANS)) == TCPCB_SACKED_RETRANS)
		goto fallback;
	if (!klp_skb_can_shift(skb))
		goto fallback;
	/* This frame is about to be dropped (was ACKed). */
	if (!after(TCP_SKB_CB(skb)->end_seq, tp->snd_una))
		goto fallback;

	/* Can only happen with delayed DSACK + discard craziness */
	if (unlikely(skb == tcp_write_queue_head(sk)))
		goto fallback;
	prev = tcp_write_queue_prev(sk, skb);

	if ((TCP_SKB_CB(prev)->sacked & TCPCB_TAGBITS) != TCPCB_SACKED_ACKED)
		goto fallback;

	if (!tcp_skb_can_collapse_to(prev))
		goto fallback;

	in_sack = !after(start_seq, TCP_SKB_CB(skb)->seq) &&
		  !before(end_seq, TCP_SKB_CB(skb)->end_seq);

	if (in_sack) {
		len = skb->len;
		pcount = tcp_skb_pcount(skb);
		mss = klp_tcp_skb_seglen(skb);

		/* TODO: Fix DSACKs to not fragment already SACKed and we can
		 * drop this restriction as unnecessary
		 */
		if (mss != klp_tcp_skb_seglen(prev))
			goto fallback;
	} else {
		if (!after(TCP_SKB_CB(skb)->end_seq, start_seq))
			goto noop;
		/* CHECKME: This is non-MSS split case only?, this will
		 * cause skipped skbs due to advancing loop btw, original
		 * has that feature too
		 */
		if (tcp_skb_pcount(skb) <= 1)
			goto noop;

		in_sack = !after(start_seq, TCP_SKB_CB(skb)->seq);
		if (!in_sack) {
			/* TODO: head merge to next could be attempted here
			 * if (!after(TCP_SKB_CB(skb)->end_seq, end_seq)),
			 * though it might not be worth of the additional hassle
			 *
			 * ...we can probably just fallback to what was done
			 * previously. We could try merging non-SACKed ones
			 * as well but it probably isn't going to buy off
			 * because later SACKs might again split them, and
			 * it would make skb timestamp tracking considerably
			 * harder problem.
			 */
			goto fallback;
		}

		len = end_seq - TCP_SKB_CB(skb)->seq;
		BUG_ON(len < 0);
		BUG_ON(len > skb->len);

		/* MSS boundaries should be honoured or else pcount will
		 * severely break even though it makes things bit trickier.
		 * Optimize common case to avoid most of the divides
		 */
		mss = tcp_skb_mss(skb);

		/* TODO: Fix DSACKs to not fragment already SACKed and we can
		 * drop this restriction as unnecessary
		 */
		if (mss != klp_tcp_skb_seglen(prev))
			goto fallback;

		if (len == mss) {
			pcount = 1;
		} else if (len < mss) {
			goto noop;
		} else {
			pcount = len / mss;
			len = pcount * mss;
		}
	}

	/* tcp_sacktag_one() won't SACK-tag ranges below snd_una */
	if (!after(TCP_SKB_CB(skb)->seq + len, tp->snd_una))
		goto fallback;

	/*
	 * Fix CVE-2019-11477
	 *  -1 line, +1 line
	 */
	if (!klp_tcp_skb_shift(prev, skb, pcount, len))
		goto fallback;
	if (!klp_tcp_shifted_skb(sk, skb, state, pcount, len, mss, dup_sack))
		goto out;

	/* Hole filled allows collapsing with the next as well, this is very
	 * useful when hole on every nth skb pattern happens
	 */
	if (prev == tcp_write_queue_tail(sk))
		goto out;
	skb = tcp_write_queue_next(sk, prev);

	if (!klp_skb_can_shift(skb) ||
	    (skb == tcp_send_head(sk)) ||
	    ((TCP_SKB_CB(skb)->sacked & TCPCB_TAGBITS) != TCPCB_SACKED_ACKED) ||
	    (mss != klp_tcp_skb_seglen(skb)))
		goto out;

	len = skb->len;
	/*
	 * Fix CVE-2019-11477
	 *  -4 lines, +5 lines
	 */
	next_pcount = tcp_skb_pcount(skb);
	if (klp_tcp_skb_shift(prev, skb, next_pcount, len)) {
		pcount += next_pcount;
		klp_tcp_shifted_skb(sk, skb, state, next_pcount, len, mss, 0);
	}

out:
	state->fack_count += pcount;
	return prev;

noop:
	return skb;

fallback:
	NET_INC_STATS(sock_net(sk), LINUX_MIB_SACKSHIFTFALLBACK);
	return NULL;
}

/* patched, calls inlined tcp_shift_skb_data */
struct sk_buff *
klp_tcp_sacktag_walk(struct sk_buff *skb, struct sock *sk,
		     struct tcp_sack_block *next_dup,
		     struct tcp_sacktag_state *state,
		     u32 start_seq, u32 end_seq,
		     bool dup_sack_in)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *tmp;

	tcp_for_write_queue_from(skb, sk) {
		int in_sack = 0;
		bool dup_sack = dup_sack_in;

		if (skb == tcp_send_head(sk))
			break;

		/* queue is in-order => we can short-circuit the walk early */
		if (!before(TCP_SKB_CB(skb)->seq, end_seq))
			break;

		if (next_dup  &&
		    before(TCP_SKB_CB(skb)->seq, next_dup->end_seq)) {
			in_sack = klp_tcp_match_skb_to_sack(sk, skb,
							    next_dup->start_seq,
							    next_dup->end_seq);
			if (in_sack > 0)
				dup_sack = true;
		}

		/* skb reference here is a bit tricky to get right, since
		 * shifting can eat and free both this skb and the next,
		 * so not even _safe variant of the loop is enough.
		 */
		if (in_sack <= 0) {
			tmp = klp_tcp_shift_skb_data(sk, skb, state,
						start_seq, end_seq, dup_sack);
			if (tmp) {
				if (tmp != skb) {
					skb = tmp;
					continue;
				}

				in_sack = 0;
			} else {
				in_sack = klp_tcp_match_skb_to_sack(sk, skb,
								    start_seq,
								    end_seq);
			}
		}

		if (unlikely(in_sack < 0))
			break;

		if (in_sack) {
			TCP_SKB_CB(skb)->sacked =
				klp_tcp_sacktag_one(sk,
						    state,
						    TCP_SKB_CB(skb)->sacked,
						    TCP_SKB_CB(skb)->seq,
						    TCP_SKB_CB(skb)->end_seq,
						    dup_sack,
						    tcp_skb_pcount(skb),
						    skb->skb_mstamp);
			klp_tcp_rate_skb_delivered(sk, skb, state->rate);

			if (!before(TCP_SKB_CB(skb)->seq,
				    tcp_highest_sack_seq(tp)))
				tcp_advance_highest_sack(sk, skb);
		}

		state->fack_count += tcp_skb_pcount(skb);
	}
	return skb;
}

/* patched */
int klp_tcp_fragment(struct sock *sk, struct sk_buff *skb, u32 len,
		     unsigned int mss_now, gfp_t gfp)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int nsize, old_factor;
	int nlen;
	u8 flags;

	if (WARN_ON(len > skb->len))
		return -EINVAL;

	nsize = skb_headlen(skb) - len;
	if (nsize < 0)
		nsize = 0;

	/*
	 * Fix CVE-2019-11478
	 *  +3 lines
	 */
	if (unlikely((sk->sk_wmem_queued >> 1) > sk->sk_sndbuf + 0x20000))
		return -ENOMEM;

	if (skb_unclone(skb, gfp))
		return -ENOMEM;

	/* Get a new skb... force flag on. */
	buff = klp_sk_stream_alloc_skb(sk, nsize, gfp, true);
	if (!buff)
		return -ENOMEM; /* We'll just try again later. */

	sk->sk_wmem_queued += buff->truesize;
	sk_mem_charge(sk, buff->truesize);
	nlen = skb->len - len - nsize;
	buff->truesize += nlen;
	skb->truesize -= nlen;

	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->tcp_flags;
	TCP_SKB_CB(skb)->tcp_flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	TCP_SKB_CB(buff)->tcp_flags = flags;
	TCP_SKB_CB(buff)->sacked = TCP_SKB_CB(skb)->sacked;
	klp_tcp_skb_fragment_eor(skb, buff);

	if (!skb_shinfo(skb)->nr_frags && skb->ip_summed != CHECKSUM_PARTIAL) {
		/* Copy and checksum data tail into the new buffer. */
		buff->csum = csum_partial_copy_nocheck(skb->data + len,
						       skb_put(buff, nsize),
						       nsize, 0);

		skb_trim(skb, len);

		skb->csum = csum_block_sub(skb->csum, buff->csum, len);
	} else {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb_split(skb, buff, len);
	}

	buff->ip_summed = skb->ip_summed;

	buff->tstamp = skb->tstamp;
	klp_tcp_fragment_tstamp(skb, buff);

	old_factor = tcp_skb_pcount(skb);

	/* Fix up tso_factor for both original and new SKB.  */
	klp_tcp_set_skb_tso_segs(skb, mss_now);
	klp_tcp_set_skb_tso_segs(buff, mss_now);

	/* Update delivered info for the new segment */
	TCP_SKB_CB(buff)->tx = TCP_SKB_CB(skb)->tx;

	/* If this packet has been sent out already, we must
	 * adjust the various packet counters.
	 */
	if (!before(tp->snd_nxt, TCP_SKB_CB(buff)->end_seq)) {
		int diff = old_factor - tcp_skb_pcount(skb) -
			tcp_skb_pcount(buff);

		if (diff)
			klp_tcp_adjust_pcount(sk, skb, diff);
	}

	/* Link BUFF into the send queue. */
	__skb_header_release(buff);
	tcp_insert_write_queue_after(skb, buff, sk);

	return 0;
}

/* patched, inlined */
static bool klp_tcp_collapse_retrans(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *next_skb = tcp_write_queue_next(sk, skb);
	int skb_size, next_skb_size;

	skb_size = skb->len;
	next_skb_size = next_skb->len;

	BUG_ON(tcp_skb_pcount(skb) != 1 || tcp_skb_pcount(next_skb) != 1);

	if (next_skb_size) {
		if (next_skb_size <= skb_availroom(skb))
			skb_copy_bits(next_skb, 0, skb_put(skb, next_skb_size),
				      next_skb_size);
		/*
		 * Fix CVE-2019-11477
		 *  -1 line, +1 line
		 */
		else if (!klp_tcp_skb_shift(skb, next_skb, 1, next_skb_size))
			return false;
	}
	tcp_highest_sack_replace(sk, next_skb, skb);

	tcp_unlink_write_queue(next_skb, sk);

	if (next_skb->ip_summed == CHECKSUM_PARTIAL)
		skb->ip_summed = CHECKSUM_PARTIAL;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		skb->csum = csum_block_add(skb->csum, next_skb->csum, skb_size);

	/* Update sequence range on original skb. */
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(next_skb)->end_seq;

	/* Merge over control information. This moves PSH/FIN etc. over */
	TCP_SKB_CB(skb)->tcp_flags |= TCP_SKB_CB(next_skb)->tcp_flags;

	/* All done, get rid of second SKB and account for it so
	 * packet counting does not break.
	 */
	TCP_SKB_CB(skb)->sacked |= TCP_SKB_CB(next_skb)->sacked & TCPCB_EVER_RETRANS;
	TCP_SKB_CB(skb)->eor = TCP_SKB_CB(next_skb)->eor;

	/* changed transmit queue under us so clear hints */
	tcp_clear_retrans_hints_partial(tp);
	if (next_skb == tp->retransmit_skb_hint)
		tp->retransmit_skb_hint = skb;

	klp_tcp_adjust_pcount(sk, next_skb, tcp_skb_pcount(next_skb));

	klp_tcp_skb_collapse_tstamp(skb, next_skb);

	sk_wmem_free_skb(sk, next_skb);
	return true;
}

/* patched, inlined, calls inlined tcp_collapes_retrans() */
static void klp_tcp_retrans_try_collapse(struct sock *sk, struct sk_buff *to,
					 int space)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = to, *tmp;
	bool first = true;

	if (!(*klp_sysctl_tcp_retrans_collapse))
		return;
	if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)
		return;

	tcp_for_write_queue_from_safe(skb, tmp, sk) {
		if (!klp_tcp_can_collapse(sk, skb))
			break;

		if (!tcp_skb_can_collapse_to(to))
			break;

		space -= skb->len;

		if (first) {
			first = false;
			continue;
		}

		if (space < 0)
			break;

		if (after(TCP_SKB_CB(skb)->end_seq, tcp_wnd_end(tp)))
			break;

		if (!klp_tcp_collapse_retrans(sk, to))
			break;
	}
}

/* patched, calls inlined tcp_retrans_try_collapse() */
int klp__tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int cur_mss;
	int diff, len, err;


	/* Inconclusive MTU probe */
	if (icsk->icsk_mtup.probe_size)
		icsk->icsk_mtup.probe_size = 0;

	/* Do not sent more than we queued. 1/4 is reserved for possible
	 * copying overhead: fragmentation, tunneling, mangling etc.
	 */
	if (atomic_read(&sk->sk_wmem_alloc) >
	    min_t(u32, sk->sk_wmem_queued + (sk->sk_wmem_queued >> 2),
		  sk->sk_sndbuf))
		return -EAGAIN;

	if (klp_skb_still_in_host_queue(sk, skb))
		return -EBUSY;

	if (before(TCP_SKB_CB(skb)->seq, tp->snd_una)) {
		if (before(TCP_SKB_CB(skb)->end_seq, tp->snd_una))
			BUG();
		if (klp_tcp_trim_head(sk, skb, tp->snd_una - TCP_SKB_CB(skb)->seq))
			return -ENOMEM;
	}

	if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
		return -EHOSTUNREACH; /* Routing failure or similar. */

	cur_mss = klp_tcp_current_mss(sk);

	/* If receiver has shrunk his window, and skb is out of
	 * new window, do not retransmit it. The exception is the
	 * case, when window is shrunk to zero. In this case
	 * our retransmit serves as a zero window probe.
	 */
	if (!before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(tp)) &&
	    TCP_SKB_CB(skb)->seq != tp->snd_una)
		return -EAGAIN;

	len = cur_mss * segs;
	if (skb->len > len) {
		if (klp_tcp_fragment(sk, skb, len, cur_mss, GFP_ATOMIC))
			return -ENOMEM; /* We'll try again later. */
	} else {
		if (skb_unclone(skb, GFP_ATOMIC))
			return -ENOMEM;

		diff = tcp_skb_pcount(skb);
		klp_tcp_set_skb_tso_segs(skb, cur_mss);
		diff -= tcp_skb_pcount(skb);
		if (diff)
			klp_tcp_adjust_pcount(sk, skb, diff);
		if (skb->len < cur_mss)
			klp_tcp_retrans_try_collapse(sk, skb, cur_mss);
	}

	/* RFC3168, section 6.1.1.1. ECN fallback */
	if ((TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN_ECN) == TCPHDR_SYN_ECN)
		klp_tcp_ecn_clear_syn(sk, skb);

	/* Update global and local TCP statistics. */
	segs = tcp_skb_pcount(skb);
	TCP_ADD_STATS(sock_net(sk), TCP_MIB_RETRANSSEGS, segs);
	if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPSYNRETRANS);
	tp->total_retrans += segs;

	/* make sure skb->data is aligned on arches that require it
	 * and check if ack-trimming & collapsing extended the headroom
	 * beyond what csum_start can cover.
	 */
	if (unlikely((NET_IP_ALIGN && ((unsigned long)skb->data & 3)) ||
		     skb_headroom(skb) >= 0xFFFF)) {
		struct sk_buff *nskb;

		nskb = __pskb_copy(skb, MAX_TCP_HEADER, GFP_ATOMIC);
		err = nskb ? klp_tcp_transmit_skb(sk, nskb, 0, GFP_ATOMIC) :
			     -ENOBUFS;
		if (!err)
			skb->skb_mstamp = tp->tcp_mstamp;
	} else {
		err = klp_tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
	}

	if (likely(!err)) {
		TCP_SKB_CB(skb)->sacked |= TCPCB_EVER_RETRANS;
	} else if (err != -EBUSY) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPRETRANSFAIL);
	}
	return err;
}



int livepatch_bsc1137597_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

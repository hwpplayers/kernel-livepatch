/*
 * livepatch_bsc1140747
 *
 * Fix for bsc#1140747
 *
 *  Upstream commits:
 *  f070ef2ac667 ("tcp: tcp_fragment() should apply sane memory limits")
 *  stable-4.4.y commit 46c7b5d6f2a5 ("tcp: refine memory limit test in
 *                                     tcp_fragment()")
 *
 *  SLE12-SP1 commits:
 *  80e84be6e13ea67f918571f28177d814e0b7e083
 *  c9064e0f8aa0d0a372c262790a14b82f013de362
 *
 *  SLE12-SP2 + SLE12-SP3 commits:
 *  02ae87c52aeb1f897503b8818c303ba84f6ffb8b
 *  a0d7e38df8ec1b2ba672f43ba14000102ae875eb
 *
 *  SLE12-SP4 + SLE15 + SLE15-SP1 commits:
 *  b7da87ac247c6944214da1fd692e72c0ddfa16e9
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
#include "livepatch_bsc1140747.h"
#include "kallsyms_relocs.h"


static struct sk_buff *(*klp_sk_stream_alloc_skb)(struct sock *sk, int size,
						  gfp_t gfp,
						  bool force_schedule);
static void (*klp_tcp_fragment_tstamp)(struct sk_buff *skb,
				       struct sk_buff *skb2);
static void (*klp_tcp_adjust_pcount)(struct sock *sk, const struct sk_buff *skb,
				     int decr);

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sk_stream_alloc_skb", (void *)&klp_sk_stream_alloc_skb },
	{ "tcp_fragment_tstamp", (void *)&klp_tcp_fragment_tstamp },
	{ "tcp_adjust_pcount", (void *)&klp_tcp_adjust_pcount },
};


/* from net/ipv4/tcp_output.c */
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
	 * Fix bsc#1140747
	 *  -1 line, +1 line
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



int livepatch_bsc1140747_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

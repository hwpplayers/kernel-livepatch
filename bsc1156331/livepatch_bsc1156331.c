/*
 * livepatch_bsc1156331
 *
 * Fix for CVE-2018-20856, bsc#1156331
 *
 *  Upstream commit:
 *  54648cf1ec2d ("block: blk_init_allocated_queue() set q->fq as NULL in the
 *                 fail case")
 *
 *  SLE12-SP1 commit:
 *  not affected
 *
 *  SLE12-SP2 and -SP3 commit:
 *  438ecbfbdcf6e19c8c5aa6f31608427cf79451ee
 *
 *  SLE12-SP4, SLE15 and SLE15-SP1 commit:
 *  8769ece87bcf3f003c550ee319bfb327333f8e5c
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1156331.h"
#include "../kallsyms_relocs.h"


/* from block/blk.h */
struct blk_flush_queue {
	unsigned int		flush_queue_delayed:1;
	unsigned int		flush_pending_idx:1;
	unsigned int		flush_running_idx:1;
	unsigned long		flush_pending_since;
	struct list_head	flush_queue[2];
	struct list_head	flush_data_in_flight;
	struct request		*flush_rq;

	/*
	 * flush_rq shares tag with this rq, both can't be active
	 * at the same time
	 */
	struct request		*orig_rq;
	spinlock_t		mq_flush_lock;
};

static struct blk_flush_queue *(*klpe_blk_alloc_flush_queue)(struct request_queue *q,
		int node, int cmd_size);
static void (*klpe_blk_free_flush_queue)(struct blk_flush_queue *q);

static int (*klpe_blk_init_rl)(struct request_list *rl, struct request_queue *q,
		gfp_t gfp_mask);

static void (*klpe_blk_timeout_work)(struct work_struct *work);


/* from block/blk-core.c */
static blk_qc_t (*klpe_blk_queue_bio)(struct request_queue *q, struct bio *bio);

/* patched */
int klpp_blk_init_allocated_queue(struct request_queue *q)
{
	WARN_ON_ONCE(q->mq_ops);

	q->fq = (*klpe_blk_alloc_flush_queue)(q, NUMA_NO_NODE, q->cmd_size);
	if (!q->fq)
		return -ENOMEM;

	if (q->init_rq_fn && q->init_rq_fn(q, q->fq->flush_rq, GFP_KERNEL))
		goto out_free_flush_queue;

	if ((*klpe_blk_init_rl)(&q->root_rl, q, GFP_KERNEL))
		goto out_exit_flush_rq;

	INIT_WORK(&q->timeout_work, (*klpe_blk_timeout_work));
	q->queue_flags		|= QUEUE_FLAG_DEFAULT;

	/*
	 * This also sets hw/phys segments, boundary and size
	 */
	blk_queue_make_request(q, (*klpe_blk_queue_bio));

	q->sg_reserved_size = INT_MAX;

	/* Protect q->elevator from elevator_change */
	mutex_lock(&q->sysfs_lock);

	/* init elevator */
	if (elevator_init(q, NULL)) {
		mutex_unlock(&q->sysfs_lock);
		goto out_exit_flush_rq;
	}

	mutex_unlock(&q->sysfs_lock);
	return 0;

out_exit_flush_rq:
	if (q->exit_rq_fn)
		q->exit_rq_fn(q, q->fq->flush_rq);
out_free_flush_queue:
	(*klpe_blk_free_flush_queue)(q->fq);
	/*
	 * Fix CVE-2018-20856
	 *  +1 line
	 */
	q->fq = NULL;
	return -ENOMEM;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "blk_alloc_flush_queue", (void *)&klpe_blk_alloc_flush_queue },
	{ "blk_free_flush_queue", (void *)&klpe_blk_free_flush_queue },
	{ "blk_init_rl", (void *)&klpe_blk_init_rl },
	{ "blk_timeout_work", (void *)&klpe_blk_timeout_work },
	{ "blk_queue_bio", (void *)&klpe_blk_queue_bio },
};

int livepatch_bsc1156331_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

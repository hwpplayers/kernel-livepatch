/*
 * livepatch_bsc1112544
 *
 * Fix for bsc#1112544
 *
 *  Upstream commit:
 *  6c7678674014 ("xen/blkfront: correct purging of persistent grants")
 *
 *  SLE12(-SP1) commit:
 *  not affected
 *
 *  SLE12-SP2 commit:
 *  49f73a52cf3ac618afc9abd5741a10a3579bdaa6
 *
 *  SLE12-SP3 commit:
 *  ec72fb8b3ad2894e4494fcd70d156e6c571386fd
 *
 *  SLE15 commit:
 *  none yet
 *
 *
 *  Copyright (c) 2018 SUSE
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

#if IS_ENABLED(CONFIG_XEN_BLKDEV_FRONTEND)

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <xen/grant_table.h>
#include <xen/interface/io/blkif.h>
#include <xen/xenbus.h>
#include "livepatch_bsc1112544.h"
#include "kallsyms_relocs.h"

#if !IS_MODULE(CONFIG_XEN_BLKDEV_FRONTEND)
#error "Live patch supports only CONFIG_XEN_BLKDEV_FRONTEND=m"
#endif

#define KLP_PATCHED_MODULE "xen_blkfront"


static struct mutex *klp_blkfront_mutex;
static struct list_head *klp_info_list;
static struct delayed_work *klp_blkfront_work;


static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "blkfront_mutex", (void *)&klp_blkfront_mutex, "xen_blkfront" },
	{ "info_list", (void *)&klp_info_list, "xen_blkfront" },
	{ "blkfront_work", (void *)&klp_blkfront_work, "xen_blkfront" },
};



/* from driver/block/xen-blkfront.c */
enum blkif_state {
	BLKIF_STATE_DISCONNECTED,
	BLKIF_STATE_CONNECTED,
	BLKIF_STATE_SUSPENDED,
};

struct grant {
	grant_ref_t gref;
	struct page *page;
	struct list_head node;
};

enum blk_req_status {
	REQ_WAITING,
	REQ_DONE,
	REQ_ERROR,
	REQ_EOPNOTSUPP,
};

struct blk_shadow {
	struct blkif_request req;
	struct request *request;
	struct grant **grants_used;
	struct grant **indirect_grants;
	struct scatterlist *sg;
	unsigned int num_sg;
	enum blk_req_status status;

	#define KLP_NO_ASSOCIATED_ID ~0UL
	/*
	 * Id of the sibling if we ever need 2 requests when handling a
	 * block I/O request
	 */
	unsigned long associated_id;
};

#define KLP_BLK_MAX_RING_SIZE	\
	__CONST_RING_SIZE(blkif, XEN_PAGE_SIZE * XENBUS_MAX_RING_GRANTS)

struct blkfront_ring_info {
	/* Lock to protect data in every ring buffer. */
	spinlock_t ring_lock;
	struct blkif_front_ring ring;
	unsigned int ring_ref[XENBUS_MAX_RING_GRANTS];
	unsigned int evtchn, irq;
	struct work_struct work;
	struct gnttab_free_callback callback;
	struct blk_shadow shadow[KLP_BLK_MAX_RING_SIZE];
	struct list_head indirect_pages;
	struct list_head grants;
	unsigned int persistent_gnts_c;
	unsigned long shadow_free;
	struct blkfront_info *dev_info;
};

struct blkfront_info
{
	struct mutex mutex;
	struct xenbus_device *xbdev;
	struct gendisk *gd;
	u16 sector_size;
	unsigned int physical_sector_size;
	int vdevice;
	blkif_vdev_t handle;
	enum blkif_state connected;
	/* Number of pages per ring buffer. */
	unsigned int nr_ring_pages;
	struct request_queue *rq;
	unsigned int feature_flush:1;
	unsigned int feature_fua:1;
	unsigned int feature_discard:1;
	unsigned int feature_secdiscard:1;
	unsigned int feature_persistent:1;
	unsigned int discard_granularity;
	unsigned int discard_alignment;
	/* Number of 4KB segments handled */
	unsigned int max_indirect_segments;
	int is_ready;
	struct blk_mq_tag_set tag_set;
	struct blkfront_ring_info *rinfo;
	unsigned int nr_rings;
	/* Save uncomplete reqs and bios for migration. */
	struct list_head requests;
	struct bio_list bio_list;
	struct list_head info_list;
};

#define KLP_GRANT_INVALID_REF	0



/* patched, inlined */
static void klp_purge_persistent_grants(struct blkfront_info *info)
{
	unsigned int i;
	unsigned long flags;

	for (i = 0; i < info->nr_rings; i++) {
		struct blkfront_ring_info *rinfo = &info->rinfo[i];
		struct grant *gnt_list_entry, *tmp;

		spin_lock_irqsave(&rinfo->ring_lock, flags);

		if (rinfo->persistent_gnts_c == 0) {
			spin_unlock_irqrestore(&rinfo->ring_lock, flags);
			continue;
		}

		list_for_each_entry_safe(gnt_list_entry, tmp, &rinfo->grants,
					 node) {
			if (gnt_list_entry->gref == KLP_GRANT_INVALID_REF ||
			    gnttab_query_foreign_access(gnt_list_entry->gref))
				continue;

			list_del(&gnt_list_entry->node);
			gnttab_end_foreign_access(gnt_list_entry->gref, 0, 0UL);
			rinfo->persistent_gnts_c--;
			/*
			 * Fix bsc#1112544
			 *  -2 lines, +2 lines
			 */
			gnt_list_entry->gref = KLP_GRANT_INVALID_REF;
			list_add_tail(&gnt_list_entry->node, &rinfo->grants);
		}

		spin_unlock_irqrestore(&rinfo->ring_lock, flags);
	}
}

/* patched, calls inlined purge_persistent_grants() */
void klp_blkfront_delay_work(struct work_struct *work)
{
	struct blkfront_info *info;
	bool need_schedule_work = false;

	mutex_lock(klp_blkfront_mutex);

	list_for_each_entry(info, klp_info_list, info_list) {
		if (info->feature_persistent) {
			need_schedule_work = true;
			mutex_lock(&info->mutex);
			klp_purge_persistent_grants(info);
			mutex_unlock(&info->mutex);
		}
	}

	if (need_schedule_work)
		schedule_delayed_work(klp_blkfront_work, HZ * 10);

	mutex_unlock(klp_blkfront_mutex);
}



static int klp_patch_bsc1112544_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, KLP_PATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block klp_patch_bsc1112544_module_nb = {
	.notifier_call = klp_patch_bsc1112544_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1112544_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(KLP_PATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&klp_patch_bsc1112544_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1112544_cleanup(void)
{
	unregister_module_notifier(&klp_patch_bsc1112544_module_nb);
}

#endif /* IS_ENABLED(CONFIG_XEN_BLKDEV_FRONTEND) */

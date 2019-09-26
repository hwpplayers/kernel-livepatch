/*
 * livepatch_bsc1151021
 *
 * Fix for CVE-2019-14835, bsc#1151021
 *
 *  Upstream commit:
 *  060423bfdee3 ("vhost: make sure log_num < in_num")
 *
 *  SLE12-SP1 commit:
 *  617cb6d91d1b0af5b49d7efd53fdc6b6dbb119b0
 *
 *  SLE12-SP2 and -SP3 commit:
 *  dd39f1c1def9fd8d6b2353a89217828f66de832d
 *
 *  SLE12-SP4 commit:
 *  b68beb095285a9626f4322784482ff2b89a8b4c7
 *
 *  SLE15 commit:
 *  b68beb095285a9626f4322784482ff2b89a8b4c7
 *
 *  SLE15-SP1 commit:
 *  b68beb095285a9626f4322784482ff2b89a8b4c7
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
#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/uio.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/cgroup.h>
#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ring.h>
#include <linux/atomic.h>
#include "livepatch_bsc1151021.h"
#include "../kallsyms_relocs.h"

#if !IS_MODULE(CONFIG_VHOST)
#error "Live patch supports only CONFIG_VHOST=m"
#endif

#define LIVEPATCHED_MODULE "vhost"


/* from drivers/vhost/vhost.h */
struct vhost_work;
typedef void (*vhost_work_fn_t)(struct vhost_work *work);

struct vhost_work {
	struct llist_node	  node;
	vhost_work_fn_t		  fn;
	wait_queue_head_t	  done;
	int			  flushing;
	unsigned		  queue_seq;
	unsigned		  done_seq;
	unsigned long		  flags;
};

struct vhost_poll {
	poll_table                table;
	wait_queue_head_t        *wqh;
	wait_queue_entry_t              wait;
	struct vhost_work	  work;
	unsigned long		  mask;
	struct vhost_dev	 *dev;
};

struct vhost_log {
	u64 addr;
	u64 len;
};

struct vhost_umem_node {
	struct rb_node rb;
	struct list_head link;
	__u64 start;
	__u64 last;
	__u64 size;
	__u64 userspace_addr;
	__u32 perm;
	__u32 flags_padding;
	__u64 __subtree_last;
};

enum vhost_uaddr_type {
	VHOST_ADDR_DESC = 0,
	VHOST_ADDR_AVAIL = 1,
	VHOST_ADDR_USED = 2,
	VHOST_NUM_ADDRS = 3,
};

struct vhost_virtqueue {
	struct vhost_dev *dev;

	/* The actual ring of buffers. */
	struct mutex mutex;
	unsigned int num;
	struct vring_desc __user *desc;
	struct vring_avail __user *avail;
	struct vring_used __user *used;
	const struct vhost_umem_node *meta_iotlb[VHOST_NUM_ADDRS];
	struct file *kick;
	struct file *call;
	struct file *error;
	struct eventfd_ctx *call_ctx;
	struct eventfd_ctx *error_ctx;
	struct eventfd_ctx *log_ctx;

	struct vhost_poll poll;

	/* The routine to call when the Guest pings us, or timeout. */
	vhost_work_fn_t handle_kick;

	/* Last available index we saw. */
	u16 last_avail_idx;

	/* Caches available index value from user. */
	u16 avail_idx;

	/* Last index we used. */
	u16 last_used_idx;

	/* Last used evet we've seen */
	u16 last_used_event;

	/* Used flags */
	u16 used_flags;

	/* Last used index value we have signalled on */
	u16 signalled_used;

	/* Last used index value we have signalled on */
	bool signalled_used_valid;

	/* Log writes to used structure. */
	bool log_used;
	u64 log_addr;

	struct iovec iov[UIO_MAXIOV];
	struct iovec iotlb_iov[64];
	struct iovec *indirect;
	struct vring_used_elem *heads;
	/* Protected by virtqueue mutex. */
	struct vhost_umem *umem;
	struct vhost_umem *iotlb;
	void *private_data;
	u64 acked_features;
	u64 acked_backend_features;
	/* Log write descriptors */
	void __user *log_base;
	struct vhost_log *log;

	/* Ring endianness. Defaults to legacy native endianness.
	 * Set to true when starting a modern virtio device. */
	bool is_le;
#ifdef CONFIG_VHOST_CROSS_ENDIAN_LEGACY
#error "klp-ccp: non-taken branch"
#endif
	u32 busyloop_timeout;
};

int klpp_vhost_get_vq_desc(struct vhost_virtqueue *,
		      struct iovec iov[], unsigned int iov_count,
		      unsigned int *out_num, unsigned int *in_num,
		      struct vhost_log *log, unsigned int *log_num);

#define vq_err(vq, fmt, ...) do {                                  \
		pr_debug(pr_fmt(fmt), ##__VA_ARGS__);       \
		if ((vq)->error_ctx)                               \
				eventfd_signal((vq)->error_ctx, 1);\
	} while (0)

#ifdef CONFIG_VHOST_CROSS_ENDIAN_LEGACY
#error "klp-ccp: non-taken branch"
#else
/* inlined */
static inline bool vhost_is_little_endian(struct vhost_virtqueue *vq)
{
	return virtio_legacy_is_little_endian() || vq->is_le;
}
#endif

/* inlined */
static inline u16 vhost16_to_cpu(struct vhost_virtqueue *vq, __virtio16 val)
{
	return __virtio16_to_cpu(vhost_is_little_endian(vq), val);
}

/* inlined */
static inline __virtio16 cpu_to_vhost16(struct vhost_virtqueue *vq, u16 val)
{
	return __cpu_to_virtio16(vhost_is_little_endian(vq), val);
}

/* inlined */
static inline u32 vhost32_to_cpu(struct vhost_virtqueue *vq, __virtio32 val)
{
	return __virtio32_to_cpu(vhost_is_little_endian(vq), val);
}

/* inlined */
static inline u64 vhost64_to_cpu(struct vhost_virtqueue *vq, __virtio64 val)
{
	return __virtio64_to_cpu(vhost_is_little_endian(vq), val);
}


/* from drivers/vhost/vhost.c */
/* inlined */
static inline void __user *vhost_vq_meta_fetch(struct vhost_virtqueue *vq,
					       u64 addr, unsigned int size,
					       int type)
{
	const struct vhost_umem_node *node = vq->meta_iotlb[type];

	if (!node)
		return NULL;

	return (void *)(uintptr_t)(node->userspace_addr + addr - node->start);
}

static int (*klpe_translate_desc)(struct vhost_virtqueue *vq, u64 addr, u32 len,
			  struct iovec iov[], int iov_size, int access);

/* inlined */
static int klpr_vhost_copy_from_user(struct vhost_virtqueue *vq, void *to,
				void __user *from, unsigned size)
{
	int ret;

	if (!vq->iotlb)
		return __copy_from_user(to, from, size);
	else {
		/* This function should be called after iotlb
		 * prefetch, which means we're sure that vq
		 * could be access through iotlb. So -EAGAIN should
		 * not happen in this case.
		 */
		void __user *uaddr = vhost_vq_meta_fetch(vq,
				     (u64)(uintptr_t)from, size,
				     VHOST_ADDR_DESC);
		struct iov_iter f;

		if (uaddr)
			return __copy_from_user(to, uaddr, size);

		ret = (*klpe_translate_desc)(vq, (u64)(uintptr_t)from, size, vq->iotlb_iov,
				     ARRAY_SIZE(vq->iotlb_iov),
				     VHOST_ACCESS_RO);
		if (ret < 0) {
			vq_err(vq, "IOTLB translation failure: uaddr "
			       "%p size 0x%llx\n", from,
			       (unsigned long long) size);
			goto out;
		}
		iov_iter_init(&f, READ, vq->iotlb_iov, ret, size);
		ret = copy_from_iter(to, size, &f);
		if (ret == size)
			ret = 0;
	}

out:
	return ret;
}

/* inlined */
static void __user *klpr___vhost_get_user_slow(struct vhost_virtqueue *vq,
					  void __user *addr, unsigned int size,
					  int type)
{
	int ret;

	ret = (*klpe_translate_desc)(vq, (u64)(uintptr_t)addr, size, vq->iotlb_iov,
			     ARRAY_SIZE(vq->iotlb_iov),
			     VHOST_ACCESS_RO);
	if (ret < 0) {
		vq_err(vq, "IOTLB translation failure: uaddr "
			"%p size 0x%llx\n", addr,
			(unsigned long long) size);
		return NULL;
	}

	if (ret != 1 || vq->iotlb_iov[0].iov_len != size) {
		vq_err(vq, "Non atomic userspace memory access: uaddr "
			"%p size 0x%llx\n", addr,
			(unsigned long long) size);
		return NULL;
	}

	return vq->iotlb_iov[0].iov_base;
}

/* inlined */
static inline void __user *klpr___vhost_get_user(struct vhost_virtqueue *vq,
					    void *addr, unsigned int size,
					    int type)
{
	void __user *uaddr = vhost_vq_meta_fetch(vq,
			     (u64)(uintptr_t)addr, size, type);
	if (uaddr)
		return uaddr;

	return klpr___vhost_get_user_slow(vq, addr, size, type);
}

/* Rewrite reference to __vhost_get_user() */
#define klpr_vhost_get_user(vq, x, ptr, type)		\
({ \
	int ret; \
	if (!vq->iotlb) { \
		ret = __get_user(x, ptr); \
	} else { \
		__typeof__(ptr) from = \
			(__typeof__(ptr)) klpr___vhost_get_user(vq, ptr, \
							   sizeof(*ptr), \
							   type); \
		if (from != NULL) \
			ret = __get_user(x, from); \
		else \
			ret = -EFAULT; \
	} \
	ret; \
})

/* Rewrite reference to vhost_get_user() */
#define klpr_vhost_get_avail(vq, x, ptr) \
	klpr_vhost_get_user(vq, x, ptr, VHOST_ADDR_AVAIL)

static int (*klpe_translate_desc)(struct vhost_virtqueue *vq, u64 addr, u32 len,
			  struct iovec iov[], int iov_size, int access);

/* inlined */
static unsigned next_desc(struct vhost_virtqueue *vq, struct vring_desc *desc)
{
	unsigned int next;

	/* If this descriptor says it doesn't chain, we're done. */
	if (!(desc->flags & cpu_to_vhost16(vq, VRING_DESC_F_NEXT)))
		return -1U;

	/* Check they're not leading us off end of descriptors. */
	next = vhost16_to_cpu(vq, desc->next);
	/* Make sure compiler knows to grab that: we don't want it changing! */
	/* We will use the result as an index in an array, so most
	 * architectures only need a compiler barrier here. */
	read_barrier_depends();

	return next;
}

/* patched, inlined */
static int klpp_get_indirect(struct vhost_virtqueue *vq,
			struct iovec iov[], unsigned int iov_size,
			unsigned int *out_num, unsigned int *in_num,
			struct vhost_log *log, unsigned int *log_num,
			struct vring_desc *indirect)
{
	struct vring_desc desc;
	unsigned int i = 0, count, found = 0;
	u32 len = vhost32_to_cpu(vq, indirect->len);
	struct iov_iter from;
	int ret, access;

	/* Sanity check */
	if (unlikely(len % sizeof desc)) {
		vq_err(vq, "Invalid length in indirect descriptor: "
		       "len 0x%llx not multiple of 0x%zx\n",
		       (unsigned long long)len,
		       sizeof desc);
		return -EINVAL;
	}

	ret = (*klpe_translate_desc)(vq, vhost64_to_cpu(vq, indirect->addr), len, vq->indirect,
			     UIO_MAXIOV, VHOST_ACCESS_RO);
	if (unlikely(ret < 0)) {
		if (ret != -EAGAIN)
			vq_err(vq, "Translation failure %d in indirect.\n", ret);
		return ret;
	}
	iov_iter_init(&from, READ, vq->indirect, ret, len);

	/* We will use the result as an address to read from, so most
	 * architectures only need a compiler barrier here. */
	read_barrier_depends();

	count = len / sizeof desc;
	/* Buffers are chained via a 16 bit next field, so
	 * we can have at most 2^16 of these. */
	if (unlikely(count > USHRT_MAX + 1)) {
		vq_err(vq, "Indirect buffer length too big: %d\n",
		       indirect->len);
		return -E2BIG;
	}

	do {
		unsigned iov_count = *in_num + *out_num;
		if (unlikely(++found > count)) {
			vq_err(vq, "Loop detected: last one at %u "
			       "indirect size %u\n",
			       i, count);
			return -EINVAL;
		}
		if (unlikely(!copy_from_iter_full(&desc, sizeof(desc), &from))) {
			vq_err(vq, "Failed indirect descriptor: idx %d, %zx\n",
			       i, (size_t)vhost64_to_cpu(vq, indirect->addr) + i * sizeof desc);
			return -EINVAL;
		}
		if (unlikely(desc.flags & cpu_to_vhost16(vq, VRING_DESC_F_INDIRECT))) {
			vq_err(vq, "Nested indirect descriptor: idx %d, %zx\n",
			       i, (size_t)vhost64_to_cpu(vq, indirect->addr) + i * sizeof desc);
			return -EINVAL;
		}

		if (desc.flags & cpu_to_vhost16(vq, VRING_DESC_F_WRITE))
			access = VHOST_ACCESS_WO;
		else
			access = VHOST_ACCESS_RO;

		ret = (*klpe_translate_desc)(vq, vhost64_to_cpu(vq, desc.addr),
				     vhost32_to_cpu(vq, desc.len), iov + iov_count,
				     iov_size - iov_count, access);
		if (unlikely(ret < 0)) {
			if (ret != -EAGAIN)
				vq_err(vq, "Translation failure %d indirect idx %d\n",
					ret, i);
			return ret;
		}
		/* If this is an input descriptor, increment that count. */
		if (access == VHOST_ACCESS_WO) {
			*in_num += ret;
			/*
			 * Fix CVE-2019-14835
			 *  -1 line, +1 line
			 */
			if (unlikely(log && ret)) {
				log[*log_num].addr = vhost64_to_cpu(vq, desc.addr);
				log[*log_num].len = vhost32_to_cpu(vq, desc.len);
				++*log_num;
			}
		} else {
			/* If it's an output descriptor, they're all supposed
			 * to come before any input descriptors. */
			if (unlikely(*in_num)) {
				vq_err(vq, "Indirect descriptor "
				       "has out after in: idx %d\n", i);
				return -EINVAL;
			}
			*out_num += ret;
		}
	} while ((i = next_desc(vq, &desc)) != -1);
	return 0;
}

/* patched */
int klpp_vhost_get_vq_desc(struct vhost_virtqueue *vq,
		      struct iovec iov[], unsigned int iov_size,
		      unsigned int *out_num, unsigned int *in_num,
		      struct vhost_log *log, unsigned int *log_num)
{
	struct vring_desc desc;
	unsigned int i, head, found = 0;
	u16 last_avail_idx;
	__virtio16 avail_idx;
	__virtio16 ring_head;
	int ret, access;

	/* Check it isn't doing very strange things with descriptor numbers. */
	last_avail_idx = vq->last_avail_idx;

	if (vq->avail_idx == vq->last_avail_idx) {
		if (unlikely(klpr_vhost_get_avail(vq, avail_idx, &vq->avail->idx))) {
			vq_err(vq, "Failed to access avail idx at %p\n",
				&vq->avail->idx);
			return -EFAULT;
		}
		vq->avail_idx = vhost16_to_cpu(vq, avail_idx);

		if (unlikely((u16)(vq->avail_idx - last_avail_idx) > vq->num)) {
			vq_err(vq, "Guest moved used index from %u to %u",
				last_avail_idx, vq->avail_idx);
			return -EFAULT;
		}

		/* If there's nothing new since last we looked, return
		 * invalid.
		 */
		if (vq->avail_idx == last_avail_idx)
			return vq->num;

		/* Only get avail ring entries after they have been
		 * exposed by guest.
		 */
		smp_rmb();
	}

	/* Grab the next descriptor number they're advertising, and increment
	 * the index we've seen. */
	if (unlikely(klpr_vhost_get_avail(vq, ring_head,
		     &vq->avail->ring[last_avail_idx & (vq->num - 1)]))) {
		vq_err(vq, "Failed to read head: idx %d address %p\n",
		       last_avail_idx,
		       &vq->avail->ring[last_avail_idx % vq->num]);
		return -EFAULT;
	}

	head = vhost16_to_cpu(vq, ring_head);

	/* If their number is silly, that's an error. */
	if (unlikely(head >= vq->num)) {
		vq_err(vq, "Guest says index %u > %u is available",
		       head, vq->num);
		return -EINVAL;
	}

	/* When we start there are none of either input nor output. */
	*out_num = *in_num = 0;
	if (unlikely(log))
		*log_num = 0;

	i = head;
	do {
		unsigned iov_count = *in_num + *out_num;
		if (unlikely(i >= vq->num)) {
			vq_err(vq, "Desc index is %u > %u, head = %u",
			       i, vq->num, head);
			return -EINVAL;
		}
		if (unlikely(++found > vq->num)) {
			vq_err(vq, "Loop detected: last one at %u "
			       "vq size %u head %u\n",
			       i, vq->num, head);
			return -EINVAL;
		}
		ret = klpr_vhost_copy_from_user(vq, &desc, vq->desc + i,
					   sizeof desc);
		if (unlikely(ret)) {
			vq_err(vq, "Failed to get descriptor: idx %d addr %p\n",
			       i, vq->desc + i);
			return -EFAULT;
		}
		if (desc.flags & cpu_to_vhost16(vq, VRING_DESC_F_INDIRECT)) {
			ret = klpp_get_indirect(vq, iov, iov_size,
					   out_num, in_num,
					   log, log_num, &desc);
			if (unlikely(ret < 0)) {
				if (ret != -EAGAIN)
					vq_err(vq, "Failure detected "
						"in indirect descriptor at idx %d\n", i);
				return ret;
			}
			continue;
		}

		if (desc.flags & cpu_to_vhost16(vq, VRING_DESC_F_WRITE))
			access = VHOST_ACCESS_WO;
		else
			access = VHOST_ACCESS_RO;
		ret = (*klpe_translate_desc)(vq, vhost64_to_cpu(vq, desc.addr),
				     vhost32_to_cpu(vq, desc.len), iov + iov_count,
				     iov_size - iov_count, access);
		if (unlikely(ret < 0)) {
			if (ret != -EAGAIN)
				vq_err(vq, "Translation failure %d descriptor idx %d\n",
					ret, i);
			return ret;
		}
		if (access == VHOST_ACCESS_WO) {
			/* If this is an input descriptor,
			 * increment that count. */
			*in_num += ret;
			/*
			 * Fix CVE-2019-14835
			 *  -1 line, +1 line
			 */
			if (unlikely(log && ret)) {
				log[*log_num].addr = vhost64_to_cpu(vq, desc.addr);
				log[*log_num].len = vhost32_to_cpu(vq, desc.len);
				++*log_num;
			}
		} else {
			/* If it's an output descriptor, they're all supposed
			 * to come before any input descriptors. */
			if (unlikely(*in_num)) {
				vq_err(vq, "Descriptor has out after in: "
				       "idx %d\n", i);
				return -EINVAL;
			}
			*out_num += ret;
		}
	} while ((i = next_desc(vq, &desc)) != -1);

	/* On success, increment avail index. */
	vq->last_avail_idx++;

	/* Assume notifications from guest are disabled at this point,
	 * if they aren't we would need to update avail_event index. */
	BUG_ON(!(vq->used_flags & VRING_USED_F_NO_NOTIFY));
	return head;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "translate_desc", (void *)&klpe_translate_desc, "vhost" },
};

static int livepatch_bsc1151021_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1151021_module_nb = {
	.notifier_call = livepatch_bsc1151021_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1151021_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1151021_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1151021_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1151021_module_nb);
}

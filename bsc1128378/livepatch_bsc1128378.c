/*
 * livepatch_bsc1128378
 *
 * Fix for CVE-2019-9213, bsc#1128378
 *
 *  Upstream commit:
 *  0a1d52994d44 ("mm: enforce min addr even if capable() in
 *                 expand_downwards()")
 *
 *  SLE12(-SP1) commit:
 *  bae6052d889aae12ed995b59036a13dc9137cc9b
 *
 *  SLE12-SP2 commit:
 *  9f06b37072f7d0a5d12146cf7a1ea5f8cfa5b4f5
 *
 *  SLE12-SP3 commit:
 *  9f06b37072f7d0a5d12146cf7a1ea5f8cfa5b4f5
 *
 *  SLE12-SP4 commit:
 *  998cff748e1cc508df25e008ae6a9fa8a9d89c63
 *
 *  SLE15 commit:
 *  998cff748e1cc508df25e008ae6a9fa8a9d89c63
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
#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/capability.h>
#include <linux/hugetlb.h>
#include <linux/rbtree_augmented.h>
#include <linux/sched/signal.h>
#include "livepatch_bsc1128378.h"
#include "kallsyms_relocs.h"

#if IS_ENABLED(CONFIG_STACK_GROWSUP)
#error "Live patch supports only CONFIG_STACK_GROWSUP=n"
#endif

#if !IS_ENABLED(CONFIG_PERF_EVENTS)
#error "Live patch supports only CONFIG_PERF_EVENTS=y"
#endif

#if !IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE)
#error "Live patch supports only CONFIG_TRANSPARENT_HUGEPAGE=y"
#endif

#ifdef CONFIG_DEBUG_VM_RB
#error "Live patch supports only CONFIG_DEBUG_VM_RB=n"
#endif

static unsigned long (*klp_mmap_min_addr);
static unsigned long (*klp_stack_guard_gap);

static int (*klp__anon_vma_prepare)(struct vm_area_struct *vma);
static bool (*klp_may_expand_vm)(struct mm_struct *mm, vm_flags_t flags,
				 unsigned long npages);

#if defined(CONFIG_PPC_MM_SLICES)
static int (*klp_is_hugepage_only_range)(struct mm_struct *mm,
					 unsigned long addr,
					 unsigned long len);
#else
#define klp_is_hugepage_only_range is_hugepage_only_range
#endif

static int (*klp_security_vm_enough_memory_mm)(struct mm_struct *mm,
					       long pages);
static void (*klp_vm_stat_account)(struct mm_struct *mm, vm_flags_t flags,
				   long npages);
static void (*klp_anon_vma_interval_tree_remove)(struct anon_vma_chain *node,
						 struct rb_root *root);
static void (*klp_anon_vma_interval_tree_insert)(struct anon_vma_chain *node,
						 struct rb_root *root);
static long (*klp_vma_compute_subtree_gap)(struct vm_area_struct *vma);
static void (*klp_perf_event_mmap)(struct vm_area_struct *vma);
static int (*klp_khugepaged_enter_vma_merge)(struct vm_area_struct *vma,
					     unsigned long vm_flags);

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "mmap_min_addr", (void *)&klp_mmap_min_addr },
	{ "stack_guard_gap", (void *)&klp_stack_guard_gap },
	{ "__anon_vma_prepare", (void *)&klp__anon_vma_prepare },
	{ "may_expand_vm", (void *)&klp_may_expand_vm },
#if defined(CONFIG_PPC_MM_SLICES)
	{ "is_hugepage_only_range", (void *)&klp_is_hugepage_only_range },
#endif
	{ "security_vm_enough_memory_mm",
	  (void *)&klp_security_vm_enough_memory_mm },
	{ "vm_stat_account", (void *)&klp_vm_stat_account },
	{ "anon_vma_interval_tree_remove",
	  (void *)&klp_anon_vma_interval_tree_remove },
	{ "anon_vma_interval_tree_insert",
	  (void *)&klp_anon_vma_interval_tree_insert },
	{ "vma_compute_subtree_gap", (void *)&klp_vma_compute_subtree_gap },
	{ "perf_event_mmap", (void *)&klp_perf_event_mmap },
	{ "khugepaged_enter_vma_merge",
	  (void *)&klp_khugepaged_enter_vma_merge },
};



/* from include/linux/rmap.h */
/* resolve reference to __anon_vma_prepare() */
static inline int klp_anon_vma_prepare(struct vm_area_struct *vma)
{
	if (likely(vma->anon_vma))
		return 0;

	return klp__anon_vma_prepare(vma);
}


/* from mm/mmap.c */
#define klp_validate_mm(mm) do { } while (0)

RB_DECLARE_CALLBACKS(static, klp_vma_gap_callbacks, struct vm_area_struct, vm_rb,
		     unsigned long, rb_subtree_gap, klp_vma_compute_subtree_gap)

/* inlined */
static void klp_vma_gap_update(struct vm_area_struct *vma)
{
	/*
	 * As it turns out, RB_DECLARE_CALLBACKS() already created a callback
	 * function that does exacltly what we want.
	 */
	klp_vma_gap_callbacks_propagate(&vma->vm_rb, NULL);
}

/* inlined */
static inline void
klp_anon_vma_interval_tree_pre_update_vma(struct vm_area_struct *vma)
{
	struct anon_vma_chain *avc;

	list_for_each_entry(avc, &vma->anon_vma_chain, same_vma)
		klp_anon_vma_interval_tree_remove(avc, &avc->anon_vma->rb_root);
}

/* inlined */
static inline void
klp_anon_vma_interval_tree_post_update_vma(struct vm_area_struct *vma)
{
	struct anon_vma_chain *avc;

	list_for_each_entry(avc, &vma->anon_vma_chain, same_vma)
		klp_anon_vma_interval_tree_insert(avc, &avc->anon_vma->rb_root);
}

/* inlined */
static int klp_acct_stack_growth(struct vm_area_struct *vma,
				 unsigned long size, unsigned long grow)
{
	struct mm_struct *mm = vma->vm_mm;
	struct rlimit *rlim = current->signal->rlim;
	unsigned long new_start;

	/* address space limit tests */
	if (!klp_may_expand_vm(mm, vma->vm_flags, grow))
		return -ENOMEM;

	/* Stack limit test */
	if (size > READ_ONCE(rlim[RLIMIT_STACK].rlim_cur))
		return -ENOMEM;

	/* mlock limit tests */
	if (vma->vm_flags & VM_LOCKED) {
		unsigned long locked;
		unsigned long limit;
		locked = mm->locked_vm + grow;
		limit = READ_ONCE(rlim[RLIMIT_MEMLOCK].rlim_cur);
		limit >>= PAGE_SHIFT;
		if (locked > limit && !capable(CAP_IPC_LOCK))
			return -ENOMEM;
	}

	/* Check to ensure the stack will not grow into a hugetlb-only region */
	new_start = (vma->vm_flags & VM_GROWSUP) ? vma->vm_start :
			vma->vm_end - size;
	if (klp_is_hugepage_only_range(vma->vm_mm, new_start, size))
		return -EFAULT;

	/*
	 * Overcommit..  This must be the final test, as it will
	 * update security statistics.
	 */
	if (klp_security_vm_enough_memory_mm(mm, grow))
		return -ENOMEM;

	return 0;
}



/* patched */
int klp_expand_downwards(struct vm_area_struct *vma,
			 unsigned long address)
{
	struct mm_struct *mm = vma->vm_mm;
	struct vm_area_struct *prev;
	unsigned long gap_addr;
	/*
	 * Fix CVE-2019-9213
	 *  -1 line, +1 line
	 */
	int error = 0;

	address &= PAGE_MASK;
	/*
	 * Fix CVE-2019-9213
	 *  -3 lines, +2 lines
	 */
	if (address < (*klp_mmap_min_addr))
		return -EPERM;

	/* Enforce stack_guard_gap */
	gap_addr = address - (*klp_stack_guard_gap);
	if (gap_addr > address)
		return -ENOMEM;
	prev = vma->vm_prev;
	if (prev && prev->vm_end > gap_addr &&
			(prev->vm_flags & (VM_WRITE|VM_READ|VM_EXEC))) {
		if (!(prev->vm_flags & VM_GROWSDOWN))
			return -ENOMEM;
		/* Check that both stack segments have the same anon_vma? */
	}

	/* We must make sure the anon_vma is allocated. */
	if (unlikely(klp_anon_vma_prepare(vma)))
		return -ENOMEM;

	/*
	 * vma->vm_start/vm_end cannot change under us because the caller
	 * is required to hold the mmap_sem in read mode.  We need the
	 * anon_vma lock to serialize against concurrent expand_stacks.
	 */
	anon_vma_lock_write(vma->anon_vma);

	/* Somebody else might have raced and expanded it already */
	if (address < vma->vm_start) {
		unsigned long size, grow;

		size = vma->vm_end - address;
		grow = (vma->vm_start - address) >> PAGE_SHIFT;

		error = -ENOMEM;
		if (grow <= vma->vm_pgoff) {
			error = klp_acct_stack_growth(vma, size, grow);
			if (!error) {
				/*
				 * vma_gap_update() doesn't support concurrent
				 * updates, but we only hold a shared mmap_sem
				 * lock here, so we need to protect against
				 * concurrent vma expansions.
				 * anon_vma_lock_write() doesn't help here, as
				 * we don't guarantee that all growable vmas
				 * in a mm share the same root anon vma.
				 * So, we reuse mm->page_table_lock to guard
				 * against concurrent vma expansions.
				 */
				spin_lock(&mm->page_table_lock);
				if (vma->vm_flags & VM_LOCKED)
					mm->locked_vm += grow;
				klp_vm_stat_account(mm, vma->vm_flags, grow);
				klp_anon_vma_interval_tree_pre_update_vma(vma);
				vma->vm_start = address;
				vma->vm_pgoff -= grow;
				klp_anon_vma_interval_tree_post_update_vma(vma);
				klp_vma_gap_update(vma);
				spin_unlock(&mm->page_table_lock);

				klp_perf_event_mmap(vma);
			}
		}
	}
	anon_vma_unlock_write(vma->anon_vma);
	klp_khugepaged_enter_vma_merge(vma, vma->vm_flags);
	klp_validate_mm(mm);
	return error;
}



int livepatch_bsc1128378_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

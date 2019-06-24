/*
 * livepatch_bsc1138264
 *
 * Fix for CVE-2019-12817, bsc#1138264
 *
 *  Upstream commit:
 *  none yet, under embargo
 *
 *  SLE12 + SLE12-SP1 commit:
 *  not affected
 *
 *  SLE12-SP2 + SLE12-SP3 commit:
 *  not affected
 * *
 *  SLE12-SP4 + SLE15 commit:
 *  not affected
 *
 *  SLE15-SP1 commit:
 *  dfe9f73d98f1e0349766a76ca31d1c3f7f98f975
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

#if IS_ENABLED(CONFIG_PPC64)

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/idr.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <asm/mmu_context.h>
#include "livepatch_bsc1138264.h"
#include "kallsyms_relocs.h"


#if !IS_ENABLED(CONFIG_PPC_BOOK3S_64)
#error "Live patch supports only CONFIG_PPC_BOOK3S_64=y"
#endif

#if !IS_ENABLED(CONFIG_PPC_SUBPAGE_PROT)
#error "Live patch supports only CONFIG_PPC_SUBPAGE_PROT=y"
#endif

#if !IS_ENABLED(CONFIG_PPC_MEM_KEYS)
#error "Live patch supports only CONFIG_PPC_MEM_KEYS=y"
#endif

#if !IS_ENABLED(CONFIG_SPAPR_TCE_IOMMU)
#error "Live patch supports only CONFIG_SPAPR_TCE_IOMMU=y"
#endif


static unsigned int (*klp_mmu_pid_bits);
static unsigned int (*klp_mmu_base_pid);
static struct prtb_entry *(*klp_process_tb);
static struct ida (*klp_mmu_context_ida);

static void (*klp_slice_init_new_context_exec)(struct mm_struct *mm);
static void (*klp_subpage_prot_init_new_context)(struct mm_struct *mm);
static void (*klp_pkey_mm_init)(struct mm_struct *mm);
static int (*klp_alloc_context_id)(int min_id, int max_id);
static void (*klp_mm_iommu_init)(struct mm_struct *mm);

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "mmu_pid_bits", (void *)&klp_mmu_pid_bits },
	{ "mmu_base_pid", (void *)&klp_mmu_base_pid },
	{ "process_tb", (void *)&klp_process_tb },
	{ "mmu_context_ida", (void *)&klp_mmu_context_ida },
	{ "slice_init_new_context_exec",
	  (void *)&klp_slice_init_new_context_exec },
	{ "subpage_prot_init_new_context",
	  (void *)&klp_subpage_prot_init_new_context },
	{ "pkey_mm_init", (void *)&klp_pkey_mm_init },
	{ "alloc_context_id", (void *)&klp_alloc_context_id },
	{ "mm_iommu_init", (void *)&klp_mm_iommu_init },
};


/* from arch/powerpc/mm/mmu_context_book3s64.c */
/* inlined */
static int klp_radix__init_new_context(struct mm_struct *mm)
{
	unsigned long rts_field;
	int index, max_id;

	max_id = (1 << (*klp_mmu_pid_bits)) - 1;
	index = klp_alloc_context_id((*klp_mmu_base_pid), max_id);
	if (index < 0)
		return index;

	/*
	 * set the process table entry,
	 */
	rts_field = radix__get_tree_size();
	(*klp_process_tb)[index].prtb0 = cpu_to_be64(rts_field | __pa(mm->pgd) | RADIX_PGD_INDEX_SIZE);

	/*
	 * Order the above store with subsequent update of the PID
	 * register (at which point HW can start loading/caching
	 * the entry) and the corresponding load by the MMU from
	 * the L2 cache.
	 */
	asm volatile("ptesync;isync" : : : "memory");

	mm->context.npu_context = NULL;

	return index;
}



/* New */
static int klp_realloc_context_ids(mm_context_t *ctx)
{
	int i, id;

	/*
	 * id 0 (aka. ctx->id) is special, we always allocate a new one, even if
	 * there wasn't one allocated previously (which happens in the exec
	 * case where ctx is newly allocated).
	 *
	 * We have to be a bit careful here. We must keep the existing ids in
	 * the array, so that we can test if they're non-zero to decide if we
	 * need to allocate a new one. However in case of error we must free the
	 * ids we've allocated but *not* any of the existing ones (or risk a
	 * UAF). That's why we decrement i at the start of the error handling
	 * loop, to skip the id that we just tested but couldn't reallocate.
	 */
	for (i = 0; i < ARRAY_SIZE(ctx->extended_id); i++) {
		if (i == 0 || ctx->extended_id[i]) {
			id = hash__alloc_context_id();
			if (id < 0)
				goto error;

			ctx->extended_id[i] = id;
		}
	}

	/* The caller expects us to return id */
	return ctx->id;

error:
	for (i--; i >= 0; i--) {
		if (ctx->extended_id[i])
			ida_free(&(*klp_mmu_context_ida), ctx->extended_id[i]);
	}

	return id;
}

/* patched, inlined */
static int klp_hash__init_new_context(struct mm_struct *mm)
{
	int index;

	/*
	 * Fix CVE-2019-12817
	 *  -3 lines
	 */

	/*
	 * The old code would re-promote on fork, we don't do that when using
	 * slices as it could cause problem promoting slices that have been
	 * forced down to 4K.
	 *
	 * For book3s we have MMU_NO_CONTEXT set to be ~0. Hence check
	 * explicitly against context.id == 0. This ensures that we properly
	 * initialize context slice details for newly allocated mm's (which will
	 * have id == 0) and don't alter context slice inherited via fork (which
	 * will have id != 0).
	 *
	 * We should not be calling init_new_context() on init_mm. Hence a
	 * check against 0 is OK.
	 */
	if (mm->context.id == 0)
		klp_slice_init_new_context_exec(mm);

	/*
	 * Fix CVE-2019-12817
	 *  +4 lines
	 */
	index = klp_realloc_context_ids(&mm->context);
	if (index < 0)
		return index;

	klp_subpage_prot_init_new_context(mm);

	klp_pkey_mm_init(mm);
	return index;
}

/* patched, calls inlined hash__init_new_context() */
int klp_init_new_context(struct task_struct *tsk, struct mm_struct *mm)
{
	int index;

	if (radix_enabled())
		index = klp_radix__init_new_context(mm);
	else
		index = klp_hash__init_new_context(mm);

	if (index < 0)
		return index;

	mm->context.id = index;

#ifdef CONFIG_PPC_64K_PAGES
	mm->context.pte_frag = NULL;
#endif
#ifdef CONFIG_SPAPR_TCE_IOMMU
	klp_mm_iommu_init(mm);
#endif
	atomic_set(&mm->context.active_cpus, 0);
	atomic_set(&mm->context.copros, 0);

	return 0;
}



int livepatch_bsc1138264_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

#endif /* IS_ENABLED(CONFIG_PPC64) */

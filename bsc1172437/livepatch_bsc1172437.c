/*
 * livepatch_bsc1172437
 *
 * Fix for CVE-2020-10757, bsc#1172437
 *
 *  Upstream commit:
 *  5bfea2d9b17f ("mm: Fix mremap not considering huge pmd devmap")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  db63514190c6eb7434f983782361074709f6380b
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  d38eb720f9c3f81e0727dce542b54e239fae5de9
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

#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/shm.h>
#include <linux/ksm.h>
#include <linux/swap.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/swapops.h>
#include <linux/highmem.h>
#include <linux/mmu_notifier.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1172437.h"
#include "../kallsyms_relocs.h"

#ifdef CONFIG_PPC64
static void (*klpe_set_pte_at)(struct mm_struct *mm, unsigned long addr, pte_t *ptep,
		pte_t pte);
#define klpr_set_pte_at (*klpe_set_pte_at)
#else
#define klpr_set_pte_at set_pte_at
#endif


/* from include/asm-generic/pgtable.h */
static void (*klpe_pgd_clear_bad)(pgd_t *);
static void (*klpe_p4d_clear_bad)(p4d_t *);
static void (*klpe_pud_clear_bad)(pud_t *);
static void (*klpe_pmd_clear_bad)(pmd_t *);

static inline int klpr_pgd_none_or_clear_bad(pgd_t *pgd)
{
	if (pgd_none(*pgd))
		return 1;
	if (unlikely(pgd_bad(*pgd))) {
		(*klpe_pgd_clear_bad)(pgd);
		return 1;
	}
	return 0;
}

static inline int klpr_p4d_none_or_clear_bad(p4d_t *p4d)
{
	if (p4d_none(*p4d))
		return 1;
	if (unlikely(p4d_bad(*p4d))) {
		(*klpe_p4d_clear_bad)(p4d);
		return 1;
	}
	return 0;
}

static inline int klpr_pud_none_or_clear_bad(pud_t *pud)
{
	if (pud_none(*pud))
		return 1;
	if (unlikely(pud_bad(*pud))) {
		(*klpe_pud_clear_bad)(pud);
		return 1;
	}
	return 0;
}

static inline int klpr_pmd_none_or_trans_huge_or_clear_bad(pmd_t *pmd)
{
	pmd_t pmdval = pmd_read_atomic(pmd);

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	barrier();
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	if (pmd_none(pmdval) || pmd_trans_huge(pmdval))
		return 1;
	if (unlikely(pmd_bad(pmdval))) {
		(*klpe_pmd_clear_bad)(pmd);
		return 1;
	}
	return 0;
}

static inline int klpr_pmd_trans_unstable(pmd_t *pmd)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	return klpr_pmd_none_or_trans_huge_or_clear_bad(pmd);
#else
#error "klp-ccp: non-taken branch"
#endif
}


/* from include/linux/huge_mm.h */
static bool (*klpe_move_huge_pmd)(struct vm_area_struct *vma, unsigned long old_addr,
			 unsigned long new_addr, unsigned long old_end,
			 pmd_t *old_pmd, pmd_t *new_pmd);

#ifdef CONFIG_TRANSPARENT_HUGEPAGE

static void (*klpe___split_huge_pmd)(struct vm_area_struct *vma, pmd_t *pmd,
		unsigned long address, bool freeze, struct page *page);

#define klpr_split_huge_pmd(__vma, __pmd, __address)				\
	do {								\
		pmd_t *____pmd = (__pmd);				\
		if (pmd_trans_huge(*____pmd)				\
					|| pmd_devmap(*____pmd))	\
			(*klpe___split_huge_pmd)(__vma, __pmd, __address, \
						false, NULL);		\
	}  while (0)

#else /* CONFIG_TRANSPARENT_HUGEPAGE */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */


/* from include/linux/mm.h */
unsigned long klpp_move_page_tables(struct vm_area_struct *vma,
		unsigned long old_addr, struct vm_area_struct *new_vma,
		unsigned long new_addr, unsigned long len,
		bool need_rmap_locks);

#ifdef __PAGETABLE_PUD_FOLDED
#error "klp-ccp: non-taken branch"
#else
static int (*klpe___pud_alloc)(struct mm_struct *mm, p4d_t *p4d, unsigned long address);
#endif

#if defined(__PAGETABLE_PMD_FOLDED) || !defined(CONFIG_MMU)
#error "klp-ccp: non-taken branch"
#else
static int (*klpe___pmd_alloc)(struct mm_struct *mm, pud_t *pud, unsigned long address);

#endif

static int (*klpe___pte_alloc)(struct mm_struct *mm, pmd_t *pmd, unsigned long address);

#if defined(CONFIG_MMU) && !defined(__ARCH_HAS_4LEVEL_HACK)

#ifndef __ARCH_HAS_5LEVEL_HACK

static inline pud_t *klpr_pud_alloc(struct mm_struct *mm, p4d_t *p4d,
		unsigned long address)
{
	return (unlikely(p4d_none(*p4d)) && (*klpe___pud_alloc)(mm, p4d, address)) ?
		NULL : pud_offset(p4d, address);
}
#else

/* from include/asm-generic/5level-fixup.h */
#define klpr_pud_alloc(mm, p4d, address) \
	((unlikely(pgd_none(*(p4d))) && (*klpe___pud_alloc)(mm, p4d, address)) ? \
		NULL : pud_offset(p4d, address))

#endif /* !__ARCH_HAS_5LEVEL_HACK */

static inline pmd_t *klpr_pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	return (unlikely(pud_none(*pud)) && (*klpe___pmd_alloc)(mm, pud, address))?
		NULL: pmd_offset(pud, address);
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_MMU && !__ARCH_HAS_4LEVEL_HACK */

#define klpr_pte_alloc(mm, pmd, address)			\
	(unlikely(pmd_none(*(pmd))) && (*klpe___pte_alloc)(mm, pmd, address))

#ifdef CONFIG_PPC64

#if USE_SPLIT_PTE_PTLOCKS

static struct page *(*klpe_pmd_page)(pmd_t pmd);

static inline spinlock_t *klpr_pte_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return ptlock_ptr((*klpe_pmd_page)(*pmd));
}

#else
#error "a preceeding branch should have been taken"
#endif

#define klpr_pte_offset_map_lock(mm, pmd, address, ptlp)	\
({							\
	spinlock_t *__ptl = klpr_pte_lockptr(mm, pmd);	\
	pte_t *__pte = pte_offset_map(pmd, address);	\
	*(ptlp) = __ptl;				\
	spin_lock(__ptl);				\
	__pte;						\
})

#else

#define klpr_pte_lockptr pte_lockptr
#define klpr_pte_offset_map_lock pte_offset_map_lock

#endif


#if defined(CONFIG_X86_64)

/* from arch/x86/include/asm/tlbflush.h */
#define klpr_flush_tlb_range(vma, start, end)	\
	(*klpe_flush_tlb_mm_range)(vma->vm_mm, start, end, vma->vm_flags)

static void (*klpe_flush_tlb_mm_range)(struct mm_struct *mm, unsigned long start,
				unsigned long end, unsigned long vmflag);

#define klpr_arch_enter_lazy_mmu_mode arch_enter_lazy_mmu_mode
#define klpr_arch_leave_lazy_mmu_mode arch_leave_lazy_mmu_mode

#elif defined(CONFIG_PPC64)

#define klpr_flush_tlb_range flush_tlb_range

/* from arch/powerpc/include/asm/book3s/64/tlbflush-hash.h */
static struct ppc64_tlb_batch __percpu (*klpe_ppc64_tlb_batch);

static void (*klpe___flush_tlb_pending)(struct ppc64_tlb_batch *batch);

static inline void klpr_arch_enter_lazy_mmu_mode(void)
{
	struct ppc64_tlb_batch *batch;

	if (radix_enabled())
		return;
	batch = this_cpu_ptr(&(*klpe_ppc64_tlb_batch));
	batch->active = 1;
}

static inline void klpr_arch_leave_lazy_mmu_mode(void)
{
	struct ppc64_tlb_batch *batch;

	if (radix_enabled())
		return;
	batch = this_cpu_ptr(&(*klpe_ppc64_tlb_batch));

	if (batch->index)
		(*klpe___flush_tlb_pending)(batch);
	batch->active = 0;
}

#else

#define klpr_flush_tlb_range flush_tlb_range
#define klpr_arch_enter_lazy_mmu_mode arch_enter_lazy_mmu_mode
#define klpr_arch_leave_lazy_mmu_mode arch_leave_lazy_mmu_mode

#endif


/* from mm/internal.h */
#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
static void (*klpe_flush_tlb_batched_pending)(struct mm_struct *mm);
#define klpr_flush_tlb_batched_pending (*klpe_flush_tlb_batched_pending)
#else
static inline void flush_tlb_batched_pending(struct mm_struct *mm)
{
}
#define klpr_flush_tlb_batched_pending flush_tlb_batched_pending
#endif /* CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH */


#ifdef CONFIG_PPC64

/* from arch/powerpc/include/asm/book3s/64/radix.h */
static void (*klpe_radix__flush_tlb_pte_p9_dd1)(unsigned long old_pte, struct mm_struct *mm,
				 unsigned long address);

static inline unsigned long klpr_radix__pte_update(struct mm_struct *mm,
					unsigned long addr,
					pte_t *ptep, unsigned long clr,
					unsigned long set,
					int huge)
{
	unsigned long old_pte;

	if (cpu_has_feature(CPU_FTR_POWER9_DD1)) {

		unsigned long new_pte;

		old_pte = __radix_pte_update(ptep, ~0ul, 0);
		/*
		 * new value of pte
		 */
		new_pte = (old_pte | set) & ~clr;
		(*klpe_radix__flush_tlb_pte_p9_dd1)(old_pte, mm, addr);
		if (new_pte)
			__radix_pte_update(ptep, 0, new_pte);
	} else
		old_pte = __radix_pte_update(ptep, clr, set);
	if (!huge)
		assert_pte_locked(mm, addr);

	return old_pte;
}

/* from arch/powerpc/include/asm/book3s/64/hash.h */
static void (*klpe_hpte_need_flush)(struct mm_struct *mm, unsigned long addr,
			    pte_t *ptep, unsigned long pte, int huge);

static inline unsigned long klpr_hash__pte_update(struct mm_struct *mm,
					 unsigned long addr,
					 pte_t *ptep, unsigned long clr,
					 unsigned long set,
					 int huge)
{
	__be64 old_be, tmp_be;
	unsigned long old;

	__asm__ __volatile__(
	"1:	ldarx	%0,0,%3		# pte_update\n\
	and.	%1,%0,%6\n\
	bne-	1b \n\
	andc	%1,%0,%4 \n\
	or	%1,%1,%7\n\
	stdcx.	%1,0,%3 \n\
	bne-	1b"
	: "=&r" (old_be), "=&r" (tmp_be), "=m" (*ptep)
	: "r" (ptep), "r" (cpu_to_be64(clr)), "m" (*ptep),
	  "r" (cpu_to_be64(H_PAGE_BUSY)), "r" (cpu_to_be64(set))
	: "cc" );
	/* huge pages use the old page table lock */
	if (!huge)
		assert_pte_locked(mm, addr);

	old = be64_to_cpu(old_be);
	if (old & H_PAGE_HASHPTE)
		(*klpe_hpte_need_flush)(mm, addr, ptep, old, huge);

	return old;
}

/* from arch/powerpc/include/asm/book3s/64/pgtable.h */
static inline unsigned long klpr_pte_update(struct mm_struct *mm, unsigned long addr,
				       pte_t *ptep, unsigned long clr,
				       unsigned long set, int huge)
{
	if (radix_enabled())
		return klpr_radix__pte_update(mm, addr, ptep, clr, set, huge);
	return klpr_hash__pte_update(mm, addr, ptep, clr, set, huge);
}

static inline pte_t klpr_ptep_get_and_clear(struct mm_struct *mm,
				       unsigned long addr, pte_t *ptep)
{
	unsigned long old = klpr_pte_update(mm, addr, ptep, ~0UL, 0, 0);
	return __pte(old);
}

#else

#define klpr_ptep_get_and_clear ptep_get_and_clear

#endif


/* from mm/mremap.c */
static pmd_t *klpr_get_old_pmd(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, addr);
	if (klpr_pgd_none_or_clear_bad(pgd))
		return NULL;

	p4d = p4d_offset(pgd, addr);
	if (klpr_p4d_none_or_clear_bad(p4d))
		return NULL;

	pud = pud_offset(p4d, addr);
	if (klpr_pud_none_or_clear_bad(pud))
		return NULL;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;

	return pmd;
}

static pmd_t *klpr_alloc_new_pmd(struct mm_struct *mm, struct vm_area_struct *vma,
			    unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, addr);
	p4d = p4d_alloc(mm, pgd, addr);
	if (!p4d)
		return NULL;
	pud = klpr_pud_alloc(mm, p4d, addr);
	if (!pud)
		return NULL;

	pmd = klpr_pmd_alloc(mm, pud, addr);
	if (!pmd)
		return NULL;

	VM_BUG_ON(pmd_trans_huge(*pmd));

	return pmd;
}

static void take_rmap_locks(struct vm_area_struct *vma)
{
	if (vma->vm_file)
		i_mmap_lock_write(vma->vm_file->f_mapping);
	if (vma->anon_vma)
		anon_vma_lock_write(vma->anon_vma);
}

static void drop_rmap_locks(struct vm_area_struct *vma)
{
	if (vma->anon_vma)
		anon_vma_unlock_write(vma->anon_vma);
	if (vma->vm_file)
		i_mmap_unlock_write(vma->vm_file->f_mapping);
}

static pte_t move_soft_dirty_pte(pte_t pte)
{

#ifdef CONFIG_MEM_SOFT_DIRTY
	if (pte_present(pte))
		pte = pte_mksoft_dirty(pte);
	else if (is_swap_pte(pte))
		pte = pte_swp_mksoft_dirty(pte);
#endif
	return pte;
}

static void klpr_move_ptes(struct vm_area_struct *vma, pmd_t *old_pmd,
		unsigned long old_addr, unsigned long old_end,
		struct vm_area_struct *new_vma, pmd_t *new_pmd,
		unsigned long new_addr, bool need_rmap_locks)
{
	struct mm_struct *mm = vma->vm_mm;
	pte_t *old_pte, *new_pte, pte;
	spinlock_t *old_ptl, *new_ptl;
	bool force_flush = false;
	unsigned long len = old_end - old_addr;

	/*
	 * When need_rmap_locks is true, we take the i_mmap_rwsem and anon_vma
	 * locks to ensure that rmap will always observe either the old or the
	 * new ptes. This is the easiest way to avoid races with
	 * truncate_pagecache(), page migration, etc...
	 *
	 * When need_rmap_locks is false, we use other ways to avoid
	 * such races:
	 *
	 * - During exec() shift_arg_pages(), we use a specially tagged vma
	 *   which rmap call sites look for using is_vma_temporary_stack().
	 *
	 * - During mremap(), new_vma is often known to be placed after vma
	 *   in rmap traversal order. This ensures rmap will always observe
	 *   either the old pte, or the new pte, or both (the page table locks
	 *   serialize access to individual ptes, but only rmap traversal
	 *   order guarantees that we won't miss both the old and new ptes).
	 */
	if (need_rmap_locks)
		take_rmap_locks(vma);

	/*
	 * We don't have to worry about the ordering of src and dst
	 * pte locks because exclusive mmap_sem prevents deadlock.
	 */
	old_pte = klpr_pte_offset_map_lock(mm, old_pmd, old_addr, &old_ptl);
	new_pte = pte_offset_map(new_pmd, new_addr);
	new_ptl = klpr_pte_lockptr(mm, new_pmd);
	if (new_ptl != old_ptl)
		spin_lock_nested(new_ptl, SINGLE_DEPTH_NESTING);
	klpr_flush_tlb_batched_pending(vma->vm_mm);
	klpr_arch_enter_lazy_mmu_mode();

	for (; old_addr < old_end; old_pte++, old_addr += PAGE_SIZE,
				   new_pte++, new_addr += PAGE_SIZE) {
		if (pte_none(*old_pte))
			continue;

		pte = klpr_ptep_get_and_clear(mm, old_addr, old_pte);
		/*
		 * If we are remapping a valid PTE, make sure
		 * to flush TLB before we drop the PTL for the
		 * PTE.
		 *
		 * NOTE! Both old and new PTL matter: the old one
		 * for racing with page_mkclean(), the new one to
		 * make sure the physical page stays valid until
		 * the TLB entry for the old mapping has been
		 * flushed.
		 */
		if (pte_present(pte))
			force_flush = true;
		pte = move_pte(pte, new_vma->vm_page_prot, old_addr, new_addr);
		pte = move_soft_dirty_pte(pte);
		klpr_set_pte_at(mm, new_addr, new_pte, pte);
	}

	klpr_arch_leave_lazy_mmu_mode();
	if (force_flush)
		klpr_flush_tlb_range(vma, old_end - len, old_end);
	if (new_ptl != old_ptl)
		spin_unlock(new_ptl);
	pte_unmap(new_pte - 1);
	pte_unmap_unlock(old_pte - 1, old_ptl);
	if (need_rmap_locks)
		drop_rmap_locks(vma);
}

unsigned long klpp_move_page_tables(struct vm_area_struct *vma,
		unsigned long old_addr, struct vm_area_struct *new_vma,
		unsigned long new_addr, unsigned long len,
		bool need_rmap_locks)
{
	unsigned long extent, next, old_end;
	pmd_t *old_pmd, *new_pmd;
	unsigned long mmun_start;	/* For mmu_notifiers */
	unsigned long mmun_end;		/* For mmu_notifiers */

	old_end = old_addr + len;
	flush_cache_range(vma, old_addr, old_end);

	mmun_start = old_addr;
	mmun_end   = old_end;
	mmu_notifier_invalidate_range_start(vma->vm_mm, mmun_start, mmun_end);

	for (; old_addr < old_end; old_addr += extent, new_addr += extent) {
		cond_resched();
		next = (old_addr + PMD_SIZE) & PMD_MASK;
		/* even if next overflowed, extent below will be ok */
		extent = next - old_addr;
		if (extent > old_end - old_addr)
			extent = old_end - old_addr;
		old_pmd = klpr_get_old_pmd(vma->vm_mm, old_addr);
		if (!old_pmd)
			continue;
		new_pmd = klpr_alloc_new_pmd(vma->vm_mm, vma, new_addr);
		if (!new_pmd)
			break;
		/*
		 * Fix CVE-2020-10757
		 *  -1 line, +1 line
		 */
		if (pmd_trans_huge(*old_pmd) || pmd_devmap(*old_pmd)) {
			if (extent == HPAGE_PMD_SIZE) {
				bool moved;
				/* See comment in move_ptes() */
				if (need_rmap_locks)
					take_rmap_locks(vma);
				moved = (*klpe_move_huge_pmd)(vma, old_addr, new_addr,
						    old_end, old_pmd, new_pmd);
				if (need_rmap_locks)
					drop_rmap_locks(vma);
				if (moved)
					continue;
			}
			klpr_split_huge_pmd(vma, old_pmd, old_addr);
			if (klpr_pmd_trans_unstable(old_pmd))
				continue;
		} else if (extent == PMD_SIZE) {
#ifdef CONFIG_HAVE_MOVE_PMD
#error "klp-ccp: non-taken branch"
#endif
		}

		if (klpr_pte_alloc(new_vma->vm_mm, new_pmd, new_addr))
			break;
		next = (new_addr + PMD_SIZE) & PMD_MASK;
		if (extent > next - new_addr)
			extent = next - new_addr;
		klpr_move_ptes(vma, old_pmd, old_addr, old_addr + extent, new_vma,
			  new_pmd, new_addr, need_rmap_locks);
	}

	mmu_notifier_invalidate_range_end(vma->vm_mm, mmun_start, mmun_end);

	return len + old_addr - old_end;	/* how much done */
}



static struct klp_kallsyms_reloc klp_funcs[] = {
#ifdef CONFIG_PPC64
	{ "set_pte_at", (void *)&klpe_set_pte_at },
#endif
	{ "pgd_clear_bad", (void *)&klpe_pgd_clear_bad },
	{ "p4d_clear_bad", (void *)&klpe_p4d_clear_bad },
	{ "pud_clear_bad", (void *)&klpe_pud_clear_bad },
	{ "pmd_clear_bad", (void *)&klpe_pmd_clear_bad },
	{ "move_huge_pmd", (void *)&klpe_move_huge_pmd },
	{ "__split_huge_pmd", (void *)&klpe___split_huge_pmd },
	{ "__pud_alloc", (void *)&klpe___pud_alloc },
	{ "__pmd_alloc", (void *)&klpe___pmd_alloc },
	{ "__pte_alloc", (void *)&klpe___pte_alloc },
#if defined(CONFIG_X86_64)
	{ "flush_tlb_mm_range", (void *)&klpe_flush_tlb_mm_range },
#elif defined(CONFIG_PPC64)
	{ "pmd_page", (void *)&klpe_pmd_page },
	{ "ppc64_tlb_batch", (void *)&klpe_ppc64_tlb_batch },
	{ "__flush_tlb_pending", (void *)&klpe___flush_tlb_pending },
#endif
#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
	{ "flush_tlb_batched_pending",
	  (void *)&klpe_flush_tlb_batched_pending },
#endif
#ifdef CONFIG_PPC64
	{ "radix__flush_tlb_pte_p9_dd1",
	  (void *)&klpe_radix__flush_tlb_pte_p9_dd1 },
	{ "hpte_need_flush", (void *)&klpe_hpte_need_flush },
#endif
};

int livepatch_bsc1172437_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

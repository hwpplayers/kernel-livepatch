/*
 * livepatch_bsc1133191_generic_gup
 *
 * Fix for CVE-2019-11487, bsc#1133191 (mm/gup.c part)
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
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/memremap.h>
#include <linux/hugetlb.h>
#include <linux/pagemap.h>
#include <linux/sched/signal.h>
#include <asm/cacheflush.h>
#include <asm/mmu_context.h>
#include "livepatch_bsc1133191_generic_gup.h"
#include "livepatch_bsc1133191_mm.h"
#include "kallsyms_relocs.h"


#if !IS_ENABLED(CONFIG_MIGRATION)
#error "Live patch suppports only CONFIG_MIGRATION=y"
#endif

#if IS_ENABLED(CONFIG_X86_64) && !defined(__HAVE_ARCH_GATE_AREA)
#error "Expected __HAVE_ARCH_GATE_AREA on x86_64"
#endif

#if IS_ENABLED(CONFIG_X86_64) && IS_ENABLED(CONFIG_HAVE_GENERIC_RCU_GUP)
#error "Expected CONFIG_HAVE_GENERIC_RCU_GUP=n on x86_64"
#endif

#if IS_ENABLED(CONFIG_PPC64) && !IS_ENABLED(CONFIG_HAVE_GENERIC_RCU_GUP)
#error "Expected CONFIG_HAVE_GENERIC_RCU_GUP=y on ppc64le"
#endif

#if IS_ENABLED(CONFIG_PPC64) && !IS_ENABLED(CONFIG_PPC_MEM_KEYS)
#error "Expected CONFIG_PPC_MEM_KEYS=y on ppc64le"
#endif

#if IS_ENABLED(CONFIG_PPC64) && defined(__PAGETABLE_PUD_FOLDED)
#error "Expected !__PAGETABLE_PUD_FOLDED on ppc64le"
#endif

#if IS_ENABLED(CONFIG_PPC64) && !USE_SPLIT_PTE_PTLOCKS
#error "Expected USE_SPLIT_PTE_PTLOCKS on ppc64le"
#endif

#if IS_ENABLED(CONFIG_HAVE_GENERIC_RCU_GUP) && !defined(__HAVE_ARCH_PTE_SPECIAL)
#error "Expected __HAVE_ARCH_PTE_SPECIAL for CONFIG_HAVE_GENERIC_RCU_GUP=y"
#endif

#if IS_ENABLED(CONFIG_HAVE_GENERIC_RCU_GUP) && !defined(__HAVE_ARCH_PTE_DEVMAP)
#error "Expected __HAVE_ARCH_PTE_DEVMAP for CONFIG_HAVE_GENERIC_RCU_GUP=y"
#endif

#if !IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE)
#error "Live patch suppports only CONFIG_TRANSPARENT_HUGEPAGE=y"
#endif

static struct mm_struct *klp_init_mm;
static struct page *(*klp_huge_zero_page);

static void (*klp_migration_entry_wait)(struct mm_struct *mm, pmd_t *pmd,
					unsigned long address);
static struct page *(*klp__vm_normal_page)(struct vm_area_struct *vma,
					   unsigned long addr,
					   pte_t pte, bool with_public_device);

#ifdef CONFIG_ZONE_DEVICE
static
struct dev_pagemap * (*klp_get_dev_pagemap)(unsigned long pfn,
					    struct dev_pagemap *pgmap);
#else
#define klp_get_dev_pagemap get_dev_pagemap
#endif

#ifdef CONFIG_PPC64
static struct page *(*klp_pmd_page)(pmd_t pmd);
static void (*klp_set_pte_at)(struct mm_struct *mm, unsigned long addr,
			      pte_t *ptep, pte_t pte);
static void (*klp_update_mmu_cache)(struct vm_area_struct *vma,
				    unsigned long address, pte_t *ptep);
static bool (*klp_arch_vma_access_permitted)(struct vm_area_struct *vma,
					     bool write, bool execute,
					     bool foreign);
static bool (*klp_arch_pte_access_permitted)(u64 pte, bool write, bool execute);
#else
#define klp_pmd_page pmd_page
#define klp_set_pte_at set_pte_at
#define klp_update_mmu_cache update_mmu_cache
#define klp_arch_vma_access_permitted arch_vma_access_permitted
#endif

static int (*klp_split_huge_page_to_list)(struct page *page,
					  struct list_head *list);
static void (*klp__split_huge_pmd)(struct vm_area_struct *vma, pmd_t *pmd,
				   unsigned long address, bool freeze,
				   struct page *page);
static void (*klp_pmd_clear_bad)(pmd_t *pmd);
static void (*klp_lru_add_drain)(void);
static void (*klp_mlock_vma_page)(struct page *page);
static struct page *(*klp_follow_huge_addr)(struct mm_struct *mm,
					    unsigned long address, int write);
static struct page *(*klp_follow_huge_pud)(struct mm_struct *mm,
					   unsigned long address, pud_t *pud,
					   int flags);

#ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
static struct page *(*klp_follow_devmap_pud)(struct vm_area_struct *vma,
					     unsigned long addr, pud_t *pud,
					     int flags);
#else
#define klp_follow_devmap_pud follow_devmap_pud
#endif

#ifdef CONFIG_X86_64
static int (*klp_pmd_huge)(pmd_t pmd);
static int (*klp_pud_huge)(pud_t pud);
#else
#define klp_pmd_huge pmd_huge
#define klp_pud_huge pud_huge
#endif

static struct page *(*klp_follow_huge_pmd)(struct mm_struct *mm,
					   unsigned long address,
					   pmd_t *pmd, int flags);
static struct page *(*klp_follow_devmap_pmd)(struct vm_area_struct *vma,
					     unsigned long addr, pmd_t *pmd,
					     int flags);
static struct page *(*klp_follow_trans_huge_pmd)(struct vm_area_struct *vma,
						 unsigned long addr,
						 pmd_t *pmd,
						 unsigned int flags);
#ifdef __HAVE_ARCH_GATE_AREA
static struct vm_area_struct *(*klp_get_gate_vma)(struct mm_struct *mm);
static int (*klp_in_gate_area)(struct mm_struct *mm, unsigned long addr);
#else
#define klp_get_gate_vma get_gate_vma
#define klp_in_gate_area in_gate_area
#endif

static pte_t *(*klp_huge_pte_offset)(struct mm_struct *mm, unsigned long addr);
static int (*klp_hugetlb_fault)(struct mm_struct *mm,
				struct vm_area_struct *vma,
				unsigned long address, unsigned int flags);

#ifdef CONFIG_HAVE_GENERIC_RCU_GUP
static void (*klp_undo_dev_pagemap)(int *nr, int nr_start, struct page **pages);
static struct page *(*klp_pud_page)(pud_t pud);
static struct page *(*klp_pgd_page)(pgd_t pgd);
#endif

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "init_mm", (void *)&klp_init_mm },
	{ "huge_zero_page", (void *)&klp_huge_zero_page },
	{ "migration_entry_wait", (void *)&klp_migration_entry_wait },
	{ "_vm_normal_page", (void *)&klp__vm_normal_page },
#ifdef CONFIG_ZONE_DEVICE
	{ "get_dev_pagemap", (void *)&klp_get_dev_pagemap },
#endif
#ifdef CONFIG_PPC64
	{ "pmd_page", (void *)&klp_pmd_page },
	{ "set_pte_at", (void *)&klp_set_pte_at },
	{ "update_mmu_cache", (void *)&klp_update_mmu_cache },
	{ "arch_vma_access_permitted", (void *)&klp_arch_vma_access_permitted },
	{ "arch_pte_access_permitted", (void *)&klp_arch_pte_access_permitted },
#endif
	{ "split_huge_page_to_list", (void *)&klp_split_huge_page_to_list },
	{ "__split_huge_pmd", (void *)&klp__split_huge_pmd },
	{ "pmd_clear_bad", (void *)&klp_pmd_clear_bad },
	{ "lru_add_drain", (void *)&klp_lru_add_drain },
	{ "mlock_vma_page", (void *)&klp_mlock_vma_page },
	{ "follow_huge_addr", (void *)&klp_follow_huge_addr },
	{ "follow_huge_pud", (void *)&klp_follow_huge_pud },
#ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
	{ "follow_devmap_pud", (void *)&klp_follow_devmap_pud },
#endif
#ifdef CONFIG_X86_64
	{ "pmd_huge", (void *)&klp_pmd_huge },
	{ "pud_huge", (void *)&klp_pud_huge },
#endif
	{ "follow_huge_pmd", (void *)&klp_follow_huge_pmd },
	{ "follow_devmap_pmd", (void *)&klp_follow_devmap_pmd },
	{ "follow_trans_huge_pmd", (void *)&klp_follow_trans_huge_pmd },
#ifdef __HAVE_ARCH_GATE_AREA
	{ "get_gate_vma", (void *)&klp_get_gate_vma },
	{ "in_gate_area", (void *)&klp_in_gate_area },
#endif
	{ "huge_pte_offset", (void *)&klp_huge_pte_offset },
	{ "hugetlb_fault", (void *)&klp_hugetlb_fault },
#ifdef CONFIG_HAVE_GENERIC_RCU_GUP
	{ "undo_dev_pagemap", (void *)&klp_undo_dev_pagemap },
	{ "pud_page", (void *)&klp_pud_page },
	{ "pgd_page", (void *)&klp_pgd_page },
#endif
};


/* from include/linux/mm.h */
/* resolve reference to non-EXPORTed _vm_normal_page() */
#define klp_vm_normal_page(vma, addr, pte) klp__vm_normal_page(vma, addr, pte, false)

#if IS_ENABLED(CONFIG_PPC64)
/* resolve to non-EXPORTed pmd_page() */
static inline spinlock_t *klp_pte_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return ptlock_ptr(klp_pmd_page(*pmd));
}

/* resolve to non-EXPORTed pmd_page() */
#define klp_pte_offset_map_lock(mm, pmd, address, ptlp)	\
({							\
	spinlock_t *__ptl = klp_pte_lockptr(mm, pmd);	\
	pte_t *__pte = pte_offset_map(pmd, address);	\
	*(ptlp) = __ptl;				\
	spin_lock(__ptl);				\
	__pte;						\
})

#else

#define klp_pte_offset_map_lock pte_offset_map_lock

#endif


/*
 * from arch/x86/include/asm/pgtable.h resp.
 * from arch/powerpc/include/asm/book3s/64/pgtable.h
 */
/* resolve to non-EXPORTed init_mm */
#define klp_pgd_offset_k(address) pgd_offset(&(*klp_init_mm), (address))


#ifdef CONFIG_PPC64
/* from arch/powerpc/include/asm/book3s/64/pgtable.h */
/* resolve to non-EXPORTed arch_pte_access_permitted() */
static inline bool klp_pte_access_permitted(pte_t pte, bool write)
{
	unsigned long pteval = pte_val(pte);
	/* Also check for pte_user */
	unsigned long clear_pte_bits = _PAGE_PRIVILEGED;
	/*
	 * _PAGE_READ is needed for any access and will be
	 * cleared for PROT_NONE
	 */
	unsigned long need_pte_bits = _PAGE_PRESENT | _PAGE_READ;

	if (write)
		need_pte_bits |= _PAGE_WRITE;

	if ((pteval & need_pte_bits) != need_pte_bits)
		return false;

	if ((pteval & clear_pte_bits) == clear_pte_bits)
		return false;

	return klp_arch_pte_access_permitted(pte_val(pte), write, 0);
}

/* resolve to non-EXPORTed arch_pte_access_permitted() */
static inline bool klp_pud_access_permitted(pud_t pud, bool write)
{
	return klp_pte_access_permitted(pud_pte(pud), write);
}

/* resolve to non-EXPORTed arch_pte_access_permitted() */
static inline bool klp_pgd_access_permitted(pgd_t pgd, bool write)
{
	return klp_pte_access_permitted(pgd_pte(pgd), write);
}

/* resolve to non-EXPORTed arch_pte_access_permitted() */
static inline bool klp_pmd_access_permitted(pmd_t pmd, bool write)
{
	return klp_pte_access_permitted(pmd_pte(pmd), write);
}

#endif


/* from mm/internal.h */
/* inlined */
static inline bool klp_is_cow_mapping(vm_flags_t flags)
{
	return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
}

/* inlined */
static inline struct page *klp_mem_map_offset(struct page *base, int offset)
{
	if (unlikely(offset >= MAX_ORDER_NR_PAGES))
		return nth_page(base, offset);
	return base + offset;
}


/* from include/linux/huge_mm.h */
/* resolve reference to non-EXPORTed split_huge_page_to_list() */
static inline int klp_split_huge_page(struct page *page)
{
	return klp_split_huge_page_to_list(page, NULL);
}

/* resolve reference to non-EXPORTed __split_huge_pmd() */
#define klp_split_huge_pmd(__vma, __pmd, __address)			\
	do {								\
		pmd_t *____pmd = (__pmd);				\
		if (pmd_trans_huge(*____pmd)				\
					|| pmd_devmap(*____pmd))	\
			klp__split_huge_pmd(__vma, __pmd, __address,	\
						false, NULL);		\
	}  while (0)

/* resolve reference to non-EXPORTed huge_zero_page */
static inline bool klp_is_huge_zero_page(struct page *page)
{
	return READ_ONCE((*klp_huge_zero_page)) == page;
}


/* from include/asm-generic/pgtable.h */
/* resolve reference to non-EXPORTed pmd_clear_bad() */
static inline int klp_pmd_none_or_trans_huge_or_clear_bad(pmd_t *pmd)
{
	pmd_t pmdval = pmd_read_atomic(pmd);
	/*
	 * The barrier will stabilize the pmdval in a register or on
	 * the stack so that it will stop changing under the code.
	 *
	 * When CONFIG_TRANSPARENT_HUGEPAGE=y on x86 32bit PAE,
	 * pmd_read_atomic is allowed to return a not atomic pmdval
	 * (for example pointing to an hugepage that has never been
	 * mapped in the pmd). The below checks will only care about
	 * the low part of the pmd with 32bit PAE x86 anyway, with the
	 * exception of pmd_none(). So the important thing is that if
	 * the low part of the pmd is found null, the high part will
	 * be also null or the pmd_none() check below would be
	 * confused.
	 */
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	barrier();
#endif
	if (pmd_none(pmdval) || pmd_trans_huge(pmdval))
		return 1;
	if (unlikely(pmd_bad(pmdval))) {
		klp_pmd_clear_bad(pmd);
		return 1;
	}
	return 0;
}

/* resolve reference to non-EXPORTed pmd_clear_bad() */
static inline int klp_pmd_trans_unstable(pmd_t *pmd)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	return klp_pmd_none_or_trans_huge_or_clear_bad(pmd);
#else
	return 0;
#endif
}


/* from mm/gup.c */
/* inlined */
static struct page *klp_no_page_table(struct vm_area_struct *vma,
		unsigned int flags)
{
	/*
	 * When core dumping an enormous anonymous area that nobody
	 * has touched so far, we don't want to allocate unnecessary pages or
	 * page tables.  Return error instead of NULL to skip handle_mm_fault,
	 * then get_dump_page() will return NULL to leave a hole in the dump.
	 * But we can only make this optimization where a hole would surely
	 * be zero-filled if handle_mm_fault() actually did handle it.
	 */
	if ((flags & FOLL_DUMP) && (!vma->vm_ops || !vma->vm_ops->fault))
		return ERR_PTR(-EFAULT);
	return NULL;
}

static int klp_follow_pfn_pte(struct vm_area_struct *vma, unsigned long address,
		pte_t *pte, unsigned int flags)
{
	/* No page to get reference */
	if (flags & FOLL_GET)
		return -EFAULT;

	if (flags & FOLL_TOUCH) {
		pte_t entry = *pte;

		if (flags & FOLL_WRITE)
			entry = pte_mkdirty(entry);
		entry = pte_mkyoung(entry);

		if (!pte_same(*pte, entry)) {
			klp_set_pte_at(vma->vm_mm, address, pte, entry);
			klp_update_mmu_cache(vma, address, pte);
		}
	}

	/* Proper page table entry exists, but no corresponding struct page */
	return -EEXIST;
}

/* inlined */
static inline bool klp_can_follow_write_pte(pte_t pte, unsigned int flags)
{
	return pte_write(pte) ||
		((flags & FOLL_FORCE) && (flags & FOLL_COW) && pte_dirty(pte));
}

/* inlined */
static int klp_faultin_page(struct task_struct *tsk, struct vm_area_struct *vma,
		unsigned long address, unsigned int *flags, int *nonblocking)
{
	unsigned int fault_flags = 0;
	int ret;

	/* mlock all present pages, but do not fault in new pages */
	if ((*flags & (FOLL_POPULATE | FOLL_MLOCK)) == FOLL_MLOCK)
		return -ENOENT;
	if (*flags & FOLL_WRITE)
		fault_flags |= FAULT_FLAG_WRITE;
	if (*flags & FOLL_REMOTE)
		fault_flags |= FAULT_FLAG_REMOTE;
	if (nonblocking)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY;
	if (*flags & FOLL_NOWAIT)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_RETRY_NOWAIT;
	if (*flags & FOLL_TRIED) {
		VM_WARN_ON_ONCE(fault_flags & FAULT_FLAG_ALLOW_RETRY);
		fault_flags |= FAULT_FLAG_TRIED;
	}

	ret = handle_mm_fault(vma, address, fault_flags);
	if (ret & VM_FAULT_ERROR) {
		int err = vm_fault_to_errno(ret, *flags);

		if (err)
			return err;
		BUG();
	}

	if (tsk) {
		if (ret & VM_FAULT_MAJOR)
			tsk->maj_flt++;
		else
			tsk->min_flt++;
	}

	if (ret & VM_FAULT_RETRY) {
		if (nonblocking)
			*nonblocking = 0;
		return -EBUSY;
	}

	/*
	 * The VM_FAULT_WRITE bit tells us that do_wp_page has broken COW when
	 * necessary, even if maybe_mkwrite decided not to set pte_write. We
	 * can thus safely do subsequent page lookups as if they were reads.
	 * But only do so when looping for pte_write is futile: in some cases
	 * userspace may also be wanting to write to the gotten user page,
	 * which a read fault here might prevent (a readonly page might get
	 * reCOWed by userspace write).
	 */
	if ((ret & VM_FAULT_WRITE) && !(vma->vm_flags & VM_WRITE))
	        *flags |= FOLL_COW;
	return 0;
}

/* inlined */
static int klp_check_vma_flags(struct vm_area_struct *vma,
			       unsigned long gup_flags)
{
	vm_flags_t vm_flags = vma->vm_flags;
	int write = (gup_flags & FOLL_WRITE);
	int foreign = (gup_flags & FOLL_REMOTE);

	if (vm_flags & (VM_IO | VM_PFNMAP))
		return -EFAULT;

	if (gup_flags & FOLL_ANON && !vma_is_anonymous(vma))
		return -EFAULT;

	if (write) {
		if (!(vm_flags & VM_WRITE)) {
			if (!(gup_flags & FOLL_FORCE))
				return -EFAULT;
			/*
			 * We used to let the write,force case do COW in a
			 * VM_MAYWRITE VM_SHARED !VM_WRITE vma, so ptrace could
			 * set a breakpoint in a read-only mapping of an
			 * executable, without corrupting the file (yet only
			 * when that file had been opened for writing!).
			 * Anon pages in shared mappings are surprising: now
			 * just reject it.
			 */
			if (!klp_is_cow_mapping(vm_flags))
				return -EFAULT;
		}
	} else if (!(vm_flags & VM_READ)) {
		if (!(gup_flags & FOLL_FORCE))
			return -EFAULT;
		/*
		 * Is there actually any vma we can reach here which does not
		 * have VM_MAYREAD set?
		 */
		if (!(vm_flags & VM_MAYREAD))
			return -EFAULT;
	}
	/*
	 * gups are always data accesses, not instruction
	 * fetches, so execute=false here
	 */
	if (!klp_arch_vma_access_permitted(vma, write, false, foreign))
		return -EFAULT;
	return 0;
}

/* inlined */
static inline pte_t klp_gup_get_pte(pte_t *ptep)
{
	return READ_ONCE(*ptep);
}

#ifdef CONFIG_HAVE_GENERIC_RCU_GUP
/* inlined */
static int klp__gup_device_huge(unsigned long pfn, unsigned long addr,
		unsigned long end, struct page **pages, int *nr)
{
	int nr_start = *nr;
	struct dev_pagemap *pgmap = NULL;

	do {
		struct page *page = pfn_to_page(pfn);

		pgmap = klp_get_dev_pagemap(pfn, pgmap);
		if (unlikely(!pgmap)) {
			klp_undo_dev_pagemap(nr, nr_start, pages);
			return 0;
		}
		SetPageReferenced(page);
		pages[*nr] = page;
		get_page(page);
		(*nr)++;
		pfn++;
	} while (addr += PAGE_SIZE, addr != end);

	if (pgmap)
		put_dev_pagemap(pgmap);
	return 1;
}

/* inlined */
static int klp__gup_device_huge_pmd(pmd_t orig, pmd_t *pmdp, unsigned long addr,
		unsigned long end, struct page **pages, int *nr)
{
	unsigned long fault_pfn;
	int nr_start = *nr;

	fault_pfn = pmd_pfn(orig) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
	if (!klp__gup_device_huge(fault_pfn, addr, end, pages, nr))
		return 0;

	if (unlikely(pmd_val(orig) != pmd_val(*pmdp))) {
		klp_undo_dev_pagemap(nr, nr_start, pages);
		return 0;
	}
	return 1;
}

/* inlined */
static int klp__gup_device_huge_pud(pud_t orig, pud_t *pudp, unsigned long addr,
		unsigned long end, struct page **pages, int *nr)
{
	unsigned long fault_pfn;
	int nr_start = *nr;

	fault_pfn = pud_pfn(orig) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
	if (!klp__gup_device_huge(fault_pfn, addr, end, pages, nr))
		return 0;

	if (unlikely(pud_val(orig) != pud_val(*pudp))) {
		klp_undo_dev_pagemap(nr, nr_start, pages);
		return 0;
	}
	return 1;
}

#endif /* CONFIG_HAVE_GENERIC_RCU_GUP */


/* from mm/hugetlb.c */
/* inlined */
static pgoff_t klp_vma_hugecache_offset(struct hstate *h,
			struct vm_area_struct *vma, unsigned long address)
{
	return ((address - vma->vm_start) >> huge_page_shift(h)) +
			(vma->vm_pgoff >> huge_page_order(h));
}

static bool klp_hugetlbfs_pagecache_present(struct hstate *h,
			struct vm_area_struct *vma, unsigned long address)
{
	struct address_space *mapping;
	pgoff_t idx;
	struct page *page;

	mapping = vma->vm_file->f_mapping;
	idx = klp_vma_hugecache_offset(h, vma, address);

	page = find_get_page(mapping, idx);
	if (page)
		put_page(page);
	return page != NULL;
}



/* patched, not inlined, but only caller, follow_page_mask(), also patched */
static struct page *klp_follow_page_pte(struct vm_area_struct *vma,
		unsigned long address, pmd_t *pmd, unsigned int flags)
{
	struct mm_struct *mm = vma->vm_mm;
	struct dev_pagemap *pgmap = NULL;
	struct page *page;
	spinlock_t *ptl;
	pte_t *ptep, pte;

retry:
	if (unlikely(pmd_bad(*pmd)))
		return klp_no_page_table(vma, flags);

	ptep = klp_pte_offset_map_lock(mm, pmd, address, &ptl);
	pte = *ptep;
	if (!pte_present(pte)) {
		swp_entry_t entry;
		/*
		 * KSM's break_ksm() relies upon recognizing a ksm page
		 * even while it is being migrated, so for that case we
		 * need migration_entry_wait().
		 */
		if (likely(!(flags & FOLL_MIGRATION)))
			goto no_page;
		if (pte_none(pte))
			goto no_page;
		entry = pte_to_swp_entry(pte);
		if (!is_migration_entry(entry))
			goto no_page;
		pte_unmap_unlock(ptep, ptl);
		klp_migration_entry_wait(mm, pmd, address);
		goto retry;
	}
	if ((flags & FOLL_NUMA) && pte_protnone(pte))
		goto no_page;
	if ((flags & FOLL_WRITE) && !klp_can_follow_write_pte(pte, flags)) {
		pte_unmap_unlock(ptep, ptl);
		return NULL;
	}

	page = klp_vm_normal_page(vma, address, pte);
	if (!page && pte_devmap(pte) && (flags & FOLL_GET)) {
		/*
		 * Only return device mapping pages in the FOLL_GET case since
		 * they are only valid while holding the pgmap reference.
		 */
		pgmap = klp_get_dev_pagemap(pte_pfn(pte), NULL);
		if (pgmap)
			page = pte_page(pte);
		else
			goto no_page;
	} else if (unlikely(!page)) {
		if (flags & FOLL_DUMP) {
			/* Avoid special (like zero) pages in core dumps */
			page = ERR_PTR(-EFAULT);
			goto out;
		}

		if (is_zero_pfn(pte_pfn(pte))) {
			page = pte_page(pte);
		} else {
			int ret;

			ret = klp_follow_pfn_pte(vma, address, ptep, flags);
			page = ERR_PTR(ret);
			goto out;
		}
	}

	if (flags & FOLL_SPLIT && PageTransCompound(page)) {
		int ret;
		get_page(page);
		pte_unmap_unlock(ptep, ptl);
		lock_page(page);
		ret = klp_split_huge_page(page);
		unlock_page(page);
		put_page(page);
		if (ret)
			return ERR_PTR(ret);
		goto retry;
	}

	if (flags & FOLL_GET) {
		/*
		 * Fix CVE-2019-11487
		 *  -1 line, +5 lines
		 */
		if (unlikely(!klp_try_get_page(page))) {
			page = ERR_PTR(-ENOMEM);
			put_dev_pagemap(pgmap);
			goto out;
		}

		/* drop the pgmap reference now that we hold the page */
		if (pgmap) {
			put_dev_pagemap(pgmap);
			pgmap = NULL;
		}
	}
	if (flags & FOLL_TOUCH) {
		if ((flags & FOLL_WRITE) &&
		    !pte_dirty(pte) && !PageDirty(page))
			set_page_dirty(page);
		/*
		 * pte_mkyoung() would be more correct here, but atomic care
		 * is needed to avoid losing the dirty bit: it is easier to use
		 * mark_page_accessed().
		 */
		mark_page_accessed(page);
	}
	if ((flags & FOLL_MLOCK) && (vma->vm_flags & VM_LOCKED)) {
		/* Do not mlock pte-mapped THP */
		if (PageTransCompound(page))
			goto out;

		/*
		 * The preliminary mapping check is mainly to avoid the
		 * pointless overhead of lock_page on the ZERO_PAGE
		 * which might bounce very badly if there is contention.
		 *
		 * If the page is already locked, we don't need to
		 * handle it now - vmscan will handle it later if and
		 * when it attempts to reclaim the page.
		 */
		if (page->mapping && trylock_page(page)) {
			klp_lru_add_drain();  /* push cached pages to LRU */
			/*
			 * Because we lock page here, and migration is
			 * blocked by the pte's page reference, and we
			 * know the page is still mapped, we don't even
			 * need to check for file-cache page truncation.
			 */
			klp_mlock_vma_page(page);
			unlock_page(page);
		}
	}
out:
	pte_unmap_unlock(ptep, ptl);
	return page;
no_page:
	pte_unmap_unlock(ptep, ptl);
	if (!pte_none(pte))
		return NULL;
	return klp_no_page_table(vma, flags);
}

/* patched */
struct page *klp_follow_page_mask(struct vm_area_struct *vma,
				  unsigned long address, unsigned int flags,
				  unsigned int *page_mask)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	spinlock_t *ptl;
	struct page *page;
	struct mm_struct *mm = vma->vm_mm;

	*page_mask = 0;

	page = klp_follow_huge_addr(mm, address, flags & FOLL_WRITE);
	if (!IS_ERR(page)) {
		BUG_ON(flags & FOLL_GET);
		return page;
	}

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		return klp_no_page_table(vma, flags);
	p4d = p4d_offset(pgd, address);
	if (p4d_none(*p4d))
		return klp_no_page_table(vma, flags);
	BUILD_BUG_ON(p4d_huge(*p4d));
	if (unlikely(p4d_bad(*p4d)))
		return klp_no_page_table(vma, flags);
	pud = pud_offset(p4d, address);
	if (pud_none(*pud))
		return klp_no_page_table(vma, flags);
	if (klp_pud_huge(*pud) && vma->vm_flags & VM_HUGETLB) {
		page = klp_follow_huge_pud(mm, address, pud, flags);
		if (page)
			return page;
		return klp_no_page_table(vma, flags);
	}
	if (pud_devmap(*pud)) {
		ptl = pud_lock(mm, pud);
		page = klp_follow_devmap_pud(vma, address, pud, flags);
		spin_unlock(ptl);
		if (page)
			return page;
	}
	if (unlikely(pud_bad(*pud)))
		return klp_no_page_table(vma, flags);

	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
		return klp_no_page_table(vma, flags);
	if (klp_pmd_huge(*pmd) && vma->vm_flags & VM_HUGETLB) {
		page = klp_follow_huge_pmd(mm, address, pmd, flags);
		if (page)
			return page;
		return klp_no_page_table(vma, flags);
	}
	if (pmd_devmap(*pmd)) {
		ptl = pmd_lock(mm, pmd);
		page = klp_follow_devmap_pmd(vma, address, pmd, flags);
		spin_unlock(ptl);
		if (page)
			return page;
	}
	if (likely(!pmd_trans_huge(*pmd)))
		return klp_follow_page_pte(vma, address, pmd, flags);

	if ((flags & FOLL_NUMA) && pmd_protnone(*pmd))
		return klp_no_page_table(vma, flags);

	ptl = pmd_lock(mm, pmd);
	if (unlikely(!pmd_trans_huge(*pmd))) {
		spin_unlock(ptl);
		return klp_follow_page_pte(vma, address, pmd, flags);
	}
	if (flags & FOLL_SPLIT) {
		int ret;
		page = klp_pmd_page(*pmd);
		if (klp_is_huge_zero_page(page)) {
			spin_unlock(ptl);
			ret = 0;
			klp_split_huge_pmd(vma, pmd, address);
			if (klp_pmd_trans_unstable(pmd))
				ret = -EBUSY;
		} else {
			/*
			 * Fix CVE-2019-11487
			 *  -1 line, +4 lines
			 */
			if (unlikely(!klp_try_get_page(page))) {
				spin_unlock(ptl);
				return ERR_PTR(-ENOMEM);
			}
			spin_unlock(ptl);
			lock_page(page);
			ret = klp_split_huge_page(page);
			unlock_page(page);
			put_page(page);
			if (pmd_none(*pmd))
				return klp_no_page_table(vma, flags);
		}

		return ret ? ERR_PTR(ret) :
			klp_follow_page_pte(vma, address, pmd, flags);
	}

	page = klp_follow_trans_huge_pmd(vma, address, pmd, flags);
	spin_unlock(ptl);
	*page_mask = HPAGE_PMD_NR - 1;
	return page;
}

/* patched, inlined */
static int klp_get_gate_page(struct mm_struct *mm, unsigned long address,
		unsigned int gup_flags, struct vm_area_struct **vma,
		struct page **page)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int ret = -EFAULT;

	/* user gate pages are read-only */
	if (gup_flags & FOLL_WRITE)
		return -EFAULT;
	if (address > TASK_SIZE)
		pgd = klp_pgd_offset_k(address);
	else
		pgd = pgd_offset_gate(mm, address);
	BUG_ON(pgd_none(*pgd));
	p4d = p4d_offset(pgd, address);
	BUG_ON(p4d_none(*p4d));
	pud = pud_offset(p4d, address);
	BUG_ON(pud_none(*pud));
	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
		return -EFAULT;
	VM_BUG_ON(pmd_trans_huge(*pmd));
	pte = pte_offset_map(pmd, address);
	if (pte_none(*pte))
		goto unmap;
	*vma = klp_get_gate_vma(mm);
	if (!page)
		goto out;
	*page = klp_vm_normal_page(*vma, address, *pte);
	if (!*page) {
		if ((gup_flags & FOLL_DUMP) || !is_zero_pfn(pte_pfn(*pte)))
			goto unmap;
		*page = pte_page(*pte);

		/*
		 * This should never happen (a device public page in the gate
		 * area).
		 */
		if (is_device_public_page(*page))
			goto unmap;
	}
	/*
	 * Fix CVE-2019-11487
	 *  -1 line, +4 lines
	 */
	if (unlikely(!klp_try_get_page(*page))) {
		ret = -ENOMEM;
		goto unmap;
	}
out:
	ret = 0;
unmap:
	pte_unmap(pte);
	return ret;
}

/*
 * patched, not inlined, but the only caller, __get_user_pages(), gets
 * also patched
 */
static
long klp_follow_hugetlb_page(struct mm_struct *mm, struct vm_area_struct *vma,
			 struct page **pages, struct vm_area_struct **vmas,
			 unsigned long *position, unsigned long *nr_pages,
			 long i, unsigned int flags, int *nonblocking)
{
	unsigned long pfn_offset;
	unsigned long vaddr = *position;
	unsigned long remainder = *nr_pages;
	struct hstate *h = hstate_vma(vma);
	int err = -EFAULT;

	while (vaddr < vma->vm_end && remainder) {
		pte_t *pte;
		spinlock_t *ptl = NULL;
		int absent;
		struct page *page;

		/*
		 * If we have a pending SIGKILL, don't keep faulting pages and
		 * potentially allocating memory.
		 */
		if (unlikely(fatal_signal_pending(current))) {
			remainder = 0;
			break;
		}

		/*
		 * Some archs (sparc64, sh*) have multiple pte_ts to
		 * each hugepage.  We have to make sure we get the
		 * first, for the page indexing below to work.
		 *
		 * Note that page table lock is not held when pte is null.
		 */
		pte = klp_huge_pte_offset(mm, vaddr & huge_page_mask(h));
		if (pte)
			ptl = huge_pte_lock(h, mm, pte);
		absent = !pte || huge_pte_none(huge_ptep_get(pte));

		/*
		 * When coredumping, it suits get_dump_page if we just return
		 * an error where there's an empty slot with no huge pagecache
		 * to back it.  This way, we avoid allocating a hugepage, and
		 * the sparse dumpfile avoids allocating disk blocks, but its
		 * huge holes still show up with zeroes where they need to be.
		 */
		if (absent && (flags & FOLL_DUMP) &&
		    !klp_hugetlbfs_pagecache_present(h, vma, vaddr)) {
			if (pte)
				spin_unlock(ptl);
			remainder = 0;
			break;
		}

		/*
		 * We need call hugetlb_fault for both hugepages under migration
		 * (in which case hugetlb_fault waits for the migration,) and
		 * hwpoisoned hugepages (in which case we need to prevent the
		 * caller from accessing to them.) In order to do this, we use
		 * here is_swap_pte instead of is_hugetlb_entry_migration and
		 * is_hugetlb_entry_hwpoisoned. This is because it simply covers
		 * both cases, and because we can't follow correct pages
		 * directly from any kind of swap entries.
		 */
		if (absent || is_swap_pte(huge_ptep_get(pte)) ||
		    ((flags & FOLL_WRITE) &&
		      !huge_pte_write(huge_ptep_get(pte)))) {
			int ret;
			unsigned int fault_flags = 0;

			if (pte)
				spin_unlock(ptl);
			if (flags & FOLL_WRITE)
				fault_flags |= FAULT_FLAG_WRITE;
			if (nonblocking)
				fault_flags |= FAULT_FLAG_ALLOW_RETRY;
			if (flags & FOLL_NOWAIT)
				fault_flags |= FAULT_FLAG_ALLOW_RETRY |
					FAULT_FLAG_RETRY_NOWAIT;
			if (flags & FOLL_TRIED) {
				VM_WARN_ON_ONCE(fault_flags &
						FAULT_FLAG_ALLOW_RETRY);
				fault_flags |= FAULT_FLAG_TRIED;
			}
			ret = klp_hugetlb_fault(mm, vma, vaddr, fault_flags);
			if (ret & VM_FAULT_ERROR) {
				err = vm_fault_to_errno(ret, flags);
				remainder = 0;
				break;
			}
			if (ret & VM_FAULT_RETRY) {
				if (nonblocking)
					*nonblocking = 0;
				*nr_pages = 0;
				/*
				 * VM_FAULT_RETRY must not return an
				 * error, it will return zero
				 * instead.
				 *
				 * No need to update "position" as the
				 * caller will not check it after
				 * *nr_pages is set to 0.
				 */
				return i;
			}
			continue;
		}

		pfn_offset = (vaddr & ~huge_page_mask(h)) >> PAGE_SHIFT;
		page = pte_page(huge_ptep_get(pte));
		/*
		 * Fix CVE-2019-11487
		 *  +12 lines
		 */
		/*
		 * Instead of doing 'try_get_page()' below in the same_page
		 * loop, just check the count once here.
		 */
		if (unlikely(page_count(page) <= 0)) {
			if (pages) {
				spin_unlock(ptl);
				remainder = 0;
				err = -ENOMEM;
				break;
			}
		}
same_page:
		if (pages) {
			pages[i] = klp_mem_map_offset(page, pfn_offset);
			get_page(pages[i]);
		}

		if (vmas)
			vmas[i] = vma;

		vaddr += PAGE_SIZE;
		++pfn_offset;
		--remainder;
		++i;
		if (vaddr < vma->vm_end && remainder &&
				pfn_offset < pages_per_huge_page(h)) {
			/*
			 * We use pfn_offset to avoid touching the pageframes
			 * of this compound page.
			 */
			goto same_page;
		}
		spin_unlock(ptl);
	}
	*nr_pages = remainder;
	/*
	 * setting position is actually required only if remainder is
	 * not zero but it's faster not to add a "if (remainder)"
	 * branch.
	 */
	*position = vaddr;

	return i ? i : err;
}

/* patched, calls inlined get_gate_page() */
long klp__get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long start, unsigned long nr_pages,
		unsigned int gup_flags, struct page **pages,
		struct vm_area_struct **vmas, int *nonblocking)
{
	long i = 0;
	unsigned int page_mask;
	struct vm_area_struct *vma = NULL;

	if (!nr_pages)
		return 0;

	VM_BUG_ON(!!pages != !!(gup_flags & FOLL_GET));

	/*
	 * If FOLL_FORCE is set then do not force a full fault as the hinting
	 * fault information is unrelated to the reference behaviour of a task
	 * using the address space
	 */
	if (!(gup_flags & FOLL_FORCE))
		gup_flags |= FOLL_NUMA;

	do {
		struct page *page;
		unsigned int foll_flags = gup_flags;
		unsigned int page_increm;

		/* first iteration or cross vma bound */
		if (!vma || start >= vma->vm_end) {
			vma = find_extend_vma(mm, start);
			if (!vma && klp_in_gate_area(mm, start)) {
				int ret;
				ret = klp_get_gate_page(mm, start & PAGE_MASK,
						gup_flags, &vma,
						pages ? &pages[i] : NULL);
				if (ret)
					return i ? : ret;
				page_mask = 0;
				goto next_page;
			}

			if (!vma || klp_check_vma_flags(vma, gup_flags))
				return i ? : -EFAULT;
			if (is_vm_hugetlb_page(vma)) {
				i = klp_follow_hugetlb_page(mm, vma, pages, vmas,
						&start, &nr_pages, i,
						gup_flags, nonblocking);
				continue;
			}
		}
retry:
		/*
		 * If we have a pending SIGKILL, don't keep faulting pages and
		 * potentially allocating memory.
		 */
		if (unlikely(fatal_signal_pending(current)))
			return i ? i : -ERESTARTSYS;
		cond_resched();
		page = klp_follow_page_mask(vma, start, foll_flags, &page_mask);
		if (!page) {
			int ret;
			ret = klp_faultin_page(tsk, vma, start, &foll_flags,
					nonblocking);
			switch (ret) {
			case 0:
				goto retry;
			case -EFAULT:
			case -ENOMEM:
			case -EHWPOISON:
				return i ? i : ret;
			case -EBUSY:
				return i;
			case -ENOENT:
				goto next_page;
			}
			BUG();
		} else if (PTR_ERR(page) == -EEXIST) {
			/*
			 * Proper page table entry exists, but no corresponding
			 * struct page.
			 */
			goto next_page;
		} else if (IS_ERR(page)) {
			return i ? i : PTR_ERR(page);
		}
		if (pages) {
			pages[i] = page;
			flush_anon_page(vma, page, start);
			flush_dcache_page(page);
			page_mask = 0;
		}
next_page:
		if (vmas) {
			vmas[i] = vma;
			page_mask = 0;
		}
		page_increm = 1 + (~(start >> PAGE_SHIFT) & page_mask);
		if (page_increm > nr_pages)
			page_increm = nr_pages;
		i += page_increm;
		start += page_increm * PAGE_SIZE;
		nr_pages -= page_increm;
	} while (nr_pages);
	return i;
}

#ifdef CONFIG_HAVE_GENERIC_RCU_GUP
/* New */
static inline struct page *klp_try_get_compound_head(struct page *page, int refs)
{
	struct page *head = compound_head(page);
	if (WARN_ON_ONCE(page_ref_count(head) < 0))
		return NULL;
	if (unlikely(!page_cache_add_speculative(head, refs)))
		return NULL;
	return head;
}

/* patched, inlined */
static int klp_gup_pte_range(pmd_t pmd, unsigned long addr, unsigned long end,
			     int write, struct page **pages, int *nr)
{
	struct dev_pagemap *pgmap = NULL;
	int nr_start = *nr, ret = 0;
	pte_t *ptep, *ptem;

	ptem = ptep = pte_offset_map(&pmd, addr);
	do {
		pte_t pte = klp_gup_get_pte(ptep);
		struct page *head, *page;

		/*
		 * Similar to the PMD case below, NUMA hinting must take slow
		 * path using the pte_protnone check.
		 */
		if (pte_protnone(pte))
			goto pte_unmap;

		if (!klp_pte_access_permitted(pte, write))
			goto pte_unmap;

		if (pte_devmap(pte)) {
			pgmap = klp_get_dev_pagemap(pte_pfn(pte), pgmap);
			if (unlikely(!pgmap)) {
				klp_undo_dev_pagemap(nr, nr_start, pages);
				goto pte_unmap;
			}
		} else if (pte_special(pte))
			goto pte_unmap;

		VM_BUG_ON(!pfn_valid(pte_pfn(pte)));
		page = pte_page(pte);
		/*
		 * Fix CVE-2019-11487
		 *  -3 lines, +2 lines
		 */
		head = klp_try_get_compound_head(page, 1);
		if (!head)
			goto pte_unmap;

		if (unlikely(pte_val(pte) != pte_val(*ptep))) {
			put_page(head);
			goto pte_unmap;
		}

		VM_BUG_ON_PAGE(compound_head(page) != head, page);

		SetPageReferenced(page);
		pages[*nr] = page;
		(*nr)++;

	} while (ptep++, addr += PAGE_SIZE, addr != end);

	ret = 1;

pte_unmap:
	if (pgmap)
		put_dev_pagemap(pgmap);
	pte_unmap(ptem);
	return ret;
}

/* patched, inlined */
static int klp_gup_huge_pmd(pmd_t orig, pmd_t *pmdp, unsigned long addr,
		unsigned long end, int write, struct page **pages, int *nr)
{
	struct page *head, *page;
	int refs;

	if (!klp_pmd_access_permitted(orig, write))
		return 0;

	if (pmd_devmap(orig))
		return klp__gup_device_huge_pmd(orig, pmdp, addr, end, pages, nr);

	refs = 0;
	/*
	 * Fix CVE-2019-11487
	 *  -2 lines, +1 line
	 */
	page = klp_pmd_page(orig) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
	do {
		/*
		 * Fix CVE-2019-11487
		 *  -1 line
		 */
		pages[*nr] = page;
		(*nr)++;
		page++;
		refs++;
	} while (addr += PAGE_SIZE, addr != end);

	/*
	 * Fix CVE-2019-11487
	 *  -1 lines, +2 lines
	 */
	head = klp_try_get_compound_head(klp_pmd_page(orig), refs);
	if (!head) {
		*nr -= refs;
		return 0;
	}

	if (unlikely(pmd_val(orig) != pmd_val(*pmdp))) {
		*nr -= refs;
		while (refs--)
			put_page(head);
		return 0;
	}

	SetPageReferenced(head);
	return 1;
}

/* patched, inlined */
static int klp_gup_huge_pud(pud_t orig, pud_t *pudp, unsigned long addr,
		unsigned long end, int write, struct page **pages, int *nr)
{
	struct page *head, *page;
	int refs;

	if (!klp_pud_access_permitted(orig, write))
		return 0;

	if (pud_devmap(orig))
		return klp__gup_device_huge_pud(orig, pudp, addr, end, pages, nr);

	refs = 0;
	/*
	 * Fix CVE-2019-11487
	 *  -2 lines, +1 line
	 */
	page = klp_pud_page(orig) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
	do {
		/*
		 * Fix CVE-2019-11487
		 *  -1 line
		 */
		pages[*nr] = page;
		(*nr)++;
		page++;
		refs++;
	} while (addr += PAGE_SIZE, addr != end);

	/*
	 * Fix CVE-2019-11487
	 *  -1 lines, +2 lines
	 */
	head = klp_try_get_compound_head(klp_pud_page(orig), refs);
	if (!head) {
		*nr -= refs;
		return 0;
	}

	if (unlikely(pud_val(orig) != pud_val(*pudp))) {
		*nr -= refs;
		while (refs--)
			put_page(head);
		return 0;
	}

	SetPageReferenced(head);
	return 1;
}

/* patched, inlined */
static int klp_gup_huge_pgd(pgd_t orig, pgd_t *pgdp, unsigned long addr,
			    unsigned long end, int write,
			    struct page **pages, int *nr)
{
	int refs;
	struct page *head, *page;

	if (!klp_pgd_access_permitted(orig, write))
		return 0;

	BUILD_BUG_ON(pgd_devmap(orig));
	refs = 0;
	/*
	 * Fix CVE-2019-11487
	 *  -2 lines, +1 line
	 */
	page = klp_pgd_page(orig) + ((addr & ~PGDIR_MASK) >> PAGE_SHIFT);
	do {
		/*
		 * Fix CVE-2019-11487
		 *  -1 line
		 */
		pages[*nr] = page;
		(*nr)++;
		page++;
		refs++;
	} while (addr += PAGE_SIZE, addr != end);

	/*
	 * Fix CVE-2019-11487
	 *  -1 lines, +2 lines
	 */
	head = klp_try_get_compound_head(klp_pgd_page(orig), refs);
	if (!head) {
		*nr -= refs;
		return 0;
	}

	if (unlikely(pgd_val(orig) != pgd_val(*pgdp))) {
		*nr -= refs;
		while (refs--)
			put_page(head);
		return 0;
	}

	SetPageReferenced(head);
	return 1;
}

/* patched, inlined, calls inlined gup_pte_range() + gup_huge_pmd() */
static int klp_gup_pmd_range(pud_t pud, unsigned long addr, unsigned long end,
			     int write, struct page **pages, int *nr)
{
	unsigned long next;
	pmd_t *pmdp;

	pmdp = pmd_offset(&pud, addr);
	do {
		pmd_t pmd = READ_ONCE(*pmdp);

		next = pmd_addr_end(addr, end);
		if (pmd_none(pmd))
			return 0;

		if (unlikely(pmd_trans_huge(pmd) || pmd_huge(pmd))) {
			/*
			 * NUMA hinting faults need to be handled in the GUP
			 * slowpath for accounting purposes and so that they
			 * can be serialised against THP migration.
			 */
			if (pmd_protnone(pmd))
				return 0;

			if (!klp_gup_huge_pmd(pmd, pmdp, addr, next, write,
				pages, nr))
				return 0;

		} else if (unlikely(is_hugepd(__hugepd(pmd_val(pmd))))) {
			/*
			 * architecture have different format for hugetlbfs
			 * pmd format and THP pmd format
			 */
			if (!gup_huge_pd(__hugepd(pmd_val(pmd)), addr,
					 PMD_SHIFT, next, write, pages, nr))
				return 0;
		} else if (!klp_gup_pte_range(pmd, addr, next, write, pages, nr))
				return 0;
	} while (pmdp++, addr = next, addr != end);

	return 1;
}

/* patched, inlined, calls inlined gup_pmd_range() + gup_huge_pud() */
static int klp_gup_pud_range(p4d_t p4d, unsigned long addr, unsigned long end,
			     int write, struct page **pages, int *nr)
{
	unsigned long next;
	pud_t *pudp;

	pudp = pud_offset(&p4d, addr);
	do {
		pud_t pud = READ_ONCE(*pudp);

		next = pud_addr_end(addr, end);
		if (pud_none(pud))
			return 0;
		if (unlikely(pud_huge(pud))) {
			if (!klp_gup_huge_pud(pud, pudp, addr, next, write,
					  pages, nr))
				return 0;
		} else if (unlikely(is_hugepd(__hugepd(pud_val(pud))))) {
			if (!gup_huge_pd(__hugepd(pud_val(pud)), addr,
					 PUD_SHIFT, next, write, pages, nr))
				return 0;
		} else if (!klp_gup_pmd_range(pud, addr, next, write, pages, nr))
			return 0;
	} while (pudp++, addr = next, addr != end);

	return 1;
}

/* patched, inlined, calls inlined gup_pud_range() */
static int klp_gup_p4d_range(pgd_t pgd, unsigned long addr, unsigned long end,
			     int write, struct page **pages, int *nr)
{
	unsigned long next;
	p4d_t *p4dp;

	p4dp = p4d_offset(&pgd, addr);
	do {
		p4d_t p4d = READ_ONCE(*p4dp);

		next = p4d_addr_end(addr, end);
		if (p4d_none(p4d))
			return 0;
		BUILD_BUG_ON(p4d_huge(p4d));
		if (unlikely(is_hugepd(__hugepd(p4d_val(p4d))))) {
			if (!gup_huge_pd(__hugepd(p4d_val(p4d)), addr,
					 P4D_SHIFT, next, write, pages, nr))
				return 0;
		} else if (!klp_gup_pud_range(p4d, addr, next, write, pages, nr))
			return 0;
	} while (p4dp++, addr = next, addr != end);

	return 1;
}

/* patched, calls inlined gup_p4d_range() + gup_huge_pgd() */
int klp__get_user_pages_fast(unsigned long start, int nr_pages, int write,
			     struct page **pages)
{
	struct mm_struct *mm = current->mm;
	unsigned long addr, len, end;
	unsigned long next, flags;
	pgd_t *pgdp;
	int nr = 0;

	start &= PAGE_MASK;
	addr = start;
	len = (unsigned long) nr_pages << PAGE_SHIFT;
	end = start + len;

	if (unlikely(!access_ok(write ? VERIFY_WRITE : VERIFY_READ,
					(void __user *)start, len)))
		return 0;

	/*
	 * Disable interrupts.  We use the nested form as we can already have
	 * interrupts disabled by get_futex_key.
	 *
	 * With interrupts disabled, we block page table pages from being
	 * freed from under us. See mmu_gather_tlb in asm-generic/tlb.h
	 * for more details.
	 *
	 * We do not adopt an rcu_read_lock(.) here as we also want to
	 * block IPIs that come from THPs splitting.
	 */

	local_irq_save(flags);
	pgdp = pgd_offset(mm, addr);
	do {
		pgd_t pgd = READ_ONCE(*pgdp);

		next = pgd_addr_end(addr, end);
		if (pgd_none(pgd))
			break;
		if (unlikely(pgd_huge(pgd))) {
			if (!klp_gup_huge_pgd(pgd, pgdp, addr, next, write,
					      pages, &nr))
				break;
		} else if (unlikely(is_hugepd(__hugepd(pgd_val(pgd))))) {
			if (!gup_huge_pd(__hugepd(pgd_val(pgd)), addr,
					 PGDIR_SHIFT, next, write, pages, &nr))
				break;
		} else if (!klp_gup_p4d_range(pgd, addr, next, write, pages, &nr))
			break;
	} while (pgdp++, addr = next, addr != end);
	local_irq_restore(flags);

	return nr;
}

#endif /* CONFIG_HAVE_GENERIC_RCU_GUP */



int livepatch_bsc1133191_generic_gup_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

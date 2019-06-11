/*
 * livepatch_bsc1133191_x86_gup
 *
 * Fix for CVE-2019-11487, bsc#1133191 (arch/x86/mm/gup.c part)
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

#ifdef CONFIG_X86_64

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/memremap.h>
#include <asm/mmu_context.h>
#include "livepatch_bsc1133191_x86_gup.h"
#include "livepatch_bsc1133191_mm.h"
#include "kallsyms_relocs.h"


static
struct dev_pagemap *(*klp_get_dev_pagemap)(unsigned long pfn,
					   struct dev_pagemap *pgmap);

static void (*klp_undo_dev_pagemap)(int *nr, int nr_start, struct page **pages);

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "get_dev_pagemap", (void *)&klp_get_dev_pagemap },
	{ "undo_dev_pagemap", (void *)&klp_undo_dev_pagemap },
};


/* from arch/x86/mm/gup.c */
/* inlined */
static inline pte_t klp_gup_get_pte(pte_t *ptep)
{
#ifndef CONFIG_X86_PAE
	return READ_ONCE(*ptep);
#else
	/*
	 * With get_user_pages_fast, we walk down the pagetables without taking
	 * any locks.  For this we would like to load the pointers atomically,
	 * but that is not possible (without expensive cmpxchg8b) on PAE.  What
	 * we do have is the guarantee that a pte will only either go from not
	 * present to present, or present to not present or both -- it will not
	 * switch to a completely different present page without a TLB flush in
	 * between; something that we are blocking by holding interrupts off.
	 *
	 * Setting ptes from not present to present goes:
	 * ptep->pte_high = h;
	 * smp_wmb();
	 * ptep->pte_low = l;
	 *
	 * And present to not present goes:
	 * ptep->pte_low = 0;
	 * smp_wmb();
	 * ptep->pte_high = 0;
	 *
	 * We must ensure here that the load of pte_low sees l iff pte_high
	 * sees h. We load pte_high *after* loading pte_low, which ensures we
	 * don't see an older value of pte_high.  *Then* we recheck pte_low,
	 * which ensures that we haven't picked up a changed pte high. We might
	 * have got rubbish values from pte_low and pte_high, but we are
	 * guaranteed that pte_low will not have the present bit set *unless*
	 * it is 'l'. And get_user_pages_fast only operates on present ptes, so
	 * we're safe.
	 *
	 * gup_get_pte should not be used or copied outside gup.c without being
	 * very careful -- it does not atomically load the pte or anything that
	 * is likely to be useful for you.
	 */
	pte_t pte;

retry:
	pte.pte_low = ptep->pte_low;
	smp_rmb();
	pte.pte_high = ptep->pte_high;
	smp_rmb();
	if (unlikely(pte.pte_low != ptep->pte_low))
		goto retry;

	return pte;
#endif
}

/* inlined */
static inline int klp_pte_allows_gup(unsigned long pteval, int write)
{
	unsigned long need_pte_bits = _PAGE_PRESENT|_PAGE_USER;

	if (write)
		need_pte_bits |= _PAGE_RW;

	if ((pteval & need_pte_bits) != need_pte_bits)
		return 0;

	/* Check memory protection keys permissions. */
	if (!__pkru_allows_pkey(pte_flags_pkey(pteval), write))
		return 0;

	return 1;
}

/* inlined */
static inline void klp_get_head_page_multiple(struct page *page, int nr)
{
	VM_BUG_ON_PAGE(page != compound_head(page), page);
	VM_BUG_ON_PAGE(page_count(page) == 0, page);
	page_ref_add(page, nr);
	SetPageReferenced(page);
}



/* patched */
int klp_gup_pte_range(pmd_t pmd, unsigned long addr,
		unsigned long end, int write, struct page **pages, int *nr)
{
	struct dev_pagemap *pgmap = NULL;
	int nr_start = *nr, ret = 0;
	pte_t *ptep, *ptem;

	/*
	 * Keep the original mapped PTE value (ptem) around since we
	 * might increment ptep off the end of the page when finishing
	 * our loop iteration.
	 */
	ptem = ptep = pte_offset_map(&pmd, addr);
	do {
		pte_t pte = klp_gup_get_pte(ptep);
		struct page *page;

		/* Similar to the PMD case, NUMA hinting must take slow path */
		if (pte_protnone(pte))
			break;

		if (!klp_pte_allows_gup(pte_val(pte), write))
			break;

		if (pte_devmap(pte)) {
			pgmap = klp_get_dev_pagemap(pte_pfn(pte), pgmap);
			if (unlikely(!pgmap)) {
				klp_undo_dev_pagemap(nr, nr_start, pages);
				break;
			}
		} else if (pte_special(pte))
			break;

		VM_BUG_ON(!pfn_valid(pte_pfn(pte)));
		page = pte_page(pte);
		/*
		 * Fix CVE-2019-11487
		 *  -1 line, +4 lines
		 */
		if (unlikely(!klp_try_get_page(page))) {
			put_dev_pagemap(pgmap);
			break;
		}
		put_dev_pagemap(pgmap);
		SetPageReferenced(page);
		pages[*nr] = page;
		(*nr)++;

	} while (ptep++, addr += PAGE_SIZE, addr != end);
	if (addr == end)
		ret = 1;
	pte_unmap(ptem);

	return ret;
}

/*
 * patched, not inlined, but all callers, __gup_device_huge_pmd() +
 * __gup_device_huge_pud(), are inlined and needed from also patched
 * functions.
 */
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
		/*
		 * Fix CVE-2019-11487
		 *  +4 lines
		 */
		if (unlikely(!klp_try_get_page(page))) {
			put_dev_pagemap(pgmap);
			return 0;
		}
		SetPageReferenced(page);
		pages[*nr] = page;
		/*
		 * Fix CVE-2019-11487
		 *  -1 line
		 */
		put_dev_pagemap(pgmap);
		(*nr)++;
		pfn++;
	} while (addr += PAGE_SIZE, addr != end);
	return 1;
}

/* not patched by itself, but inlined + caller of patched __gup_device_huge() */
static int klp__gup_device_huge_pmd(pmd_t pmd, unsigned long addr,
		unsigned long end, struct page **pages, int *nr)
{
	unsigned long fault_pfn;

	fault_pfn = pmd_pfn(pmd) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
	return klp__gup_device_huge(fault_pfn, addr, end, pages, nr);
}

/* not patched by itself, but inlined + caller of patched __gup_device_huge() */
static int klp__gup_device_huge_pud(pud_t pud, unsigned long addr,
		unsigned long end, struct page **pages, int *nr)
{
	unsigned long fault_pfn;

	fault_pfn = pud_pfn(pud) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
	return klp__gup_device_huge(fault_pfn, addr, end, pages, nr);
}

/* patched */
int klp_gup_huge_pmd(pmd_t pmd, unsigned long addr,
		unsigned long end, int write, struct page **pages, int *nr)
{
	struct page *head, *page;
	int refs;

	if (!klp_pte_allows_gup(pmd_val(pmd), write))
		return 0;

	VM_BUG_ON(!pfn_valid(pmd_pfn(pmd)));
	if (pmd_devmap(pmd))
		return klp__gup_device_huge_pmd(pmd, addr, end, pages, nr);

	/* hugepages are never "special" */
	VM_BUG_ON(pmd_flags(pmd) & _PAGE_SPECIAL);

	refs = 0;
	head = pmd_page(pmd);
	/*
	 * Fix CVE-2019-11487
	 *  +2 lines
	 */
	if (WARN_ON_ONCE(page_ref_count(head) <= 0))
		return 0;
	page = head + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
	do {
		VM_BUG_ON_PAGE(compound_head(page) != head, page);
		pages[*nr] = page;
		(*nr)++;
		page++;
		refs++;
	} while (addr += PAGE_SIZE, addr != end);
	klp_get_head_page_multiple(head, refs);

	return 1;
}

/* patched */
int klp_gup_huge_pud(pud_t pud, unsigned long addr,
		unsigned long end, int write, struct page **pages, int *nr)
{
	struct page *head, *page;
	int refs;

	if (!klp_pte_allows_gup(pud_val(pud), write))
		return 0;

	VM_BUG_ON(!pfn_valid(pud_pfn(pud)));
	if (pud_devmap(pud))
		return klp__gup_device_huge_pud(pud, addr, end, pages, nr);

	/* hugepages are never "special" */
	VM_BUG_ON(pud_flags(pud) & _PAGE_SPECIAL);

	refs = 0;
	head = pud_page(pud);
	/*
	 * Fix CVE-2019-11487
	 *  +2 lines
	 */
	if (WARN_ON_ONCE(page_ref_count(head) <= 0))
		return 0;
	page = head + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
	do {
		VM_BUG_ON_PAGE(compound_head(page) != head, page);
		pages[*nr] = page;
		(*nr)++;
		page++;
		refs++;
	} while (addr += PAGE_SIZE, addr != end);
	klp_get_head_page_multiple(head, refs);

	return 1;
}



int livepatch_bsc1133191_x86_gup_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

#endif /* CONFIG_X86_64 */

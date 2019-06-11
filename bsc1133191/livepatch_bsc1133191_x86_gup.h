#ifndef _LIVEPATCH_BSC1133191_X86_GUP_H
#define _LIVEPATCH_BSC1133191_X86_GUP_H

#ifdef CONFIG_X86_64

int livepatch_bsc1133191_x86_gup_init(void);
static inline void livepatch_bsc1133191_x86_gup_cleanup(void) {}


struct page;

int klp_gup_pte_range(pmd_t pmd, unsigned long addr,
		unsigned long end, int write, struct page **pages, int *nr);
int klp_gup_huge_pmd(pmd_t pmd, unsigned long addr,
		unsigned long end, int write, struct page **pages, int *nr);
int klp_gup_huge_pud(pud_t pud, unsigned long addr,
		unsigned long end, int write, struct page **pages, int *nr);

#else /* CONFIG_X86_64 */

static inline int livepatch_bsc1133191_x86_gup_init(void) { return 0; }
static inline void livepatch_bsc1133191_x86_gup_cleanup(void) {}

#define LIVEPATCH_BSC1133191_X86_GUP_FUNCS

#endif /* CONFIG_X86_64 */

#endif /* _LIVEPATCH_BSC1133191_X86_GUP_H */

#ifndef _LIVEPATCH_BSC1133191_GENERIC_GUP_H
#define _LIVEPATCH_BSC1133191_GENERIC_GUP_H

int livepatch_bsc1133191_generic_gup_init(void);
static inline void livepatch_bsc1133191_generic_gup_cleanup(void) {}


struct vm_area_struct;
struct task_struct;
struct mm_struct;

struct page *klp_follow_page_mask(struct vm_area_struct *vma,
				  unsigned long address, unsigned int flags,
				  unsigned int *page_mask);

long klp__get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long start, unsigned long nr_pages,
		unsigned int gup_flags, struct page **pages,
		struct vm_area_struct **vmas, int *nonblocking);

#ifdef CONFIG_HAVE_GENERIC_RCU_GUP
int klp__get_user_pages_fast(unsigned long start, int nr_pages, int write,
			     struct page **pages);
#endif

#endif /* _LIVEPATCH_BSC1133191_GENERIC_GUP_H */

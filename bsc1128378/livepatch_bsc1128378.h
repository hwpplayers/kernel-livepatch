#ifndef _LIVEPATCH_BSC1128378_H
#define _LIVEPATCH_BSC1128378_H

int livepatch_bsc1128378_init(void);
static inline void livepatch_bsc1128378_cleanup(void) {}


struct vm_area_struct;

int klp_expand_downwards(struct vm_area_struct *vma,
			 unsigned long address);

#endif /* _LIVEPATCH_BSC1128378_H */

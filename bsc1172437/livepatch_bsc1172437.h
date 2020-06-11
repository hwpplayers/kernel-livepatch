#ifndef _LIVEPATCH_BSC1172437_H
#define _LIVEPATCH_BSC1172437_H

int livepatch_bsc1172437_init(void);
static inline void livepatch_bsc1172437_cleanup(void) {}


struct vm_area_struct;

unsigned long klpp_move_page_tables(struct vm_area_struct *vma,
		unsigned long old_addr, struct vm_area_struct *new_vma,
		unsigned long new_addr, unsigned long len,
		bool need_rmap_locks);

#endif /* _LIVEPATCH_BSC1172437_H */

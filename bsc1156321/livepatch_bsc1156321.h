#ifndef _LIVEPATCH_BSC1156321_H
#define _LIVEPATCH_BSC1156321_H

int livepatch_bsc1156321_init(void);
static inline void livepatch_bsc1156321_cleanup(void) {}


struct task_struct;

int klpp_ptrace_attach(struct task_struct *task, long request,
			 unsigned long addr,
			 unsigned long flags);

int klpp_ptrace_traceme(void);

#endif /* _LIVEPATCH_BSC1156321_H */

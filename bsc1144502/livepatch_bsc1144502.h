#ifndef _LIVEPATCH_BSC1144502_H
#define _LIVEPATCH_BSC1144502_H

#if IS_ENABLED(CONFIG_X86_64)

int livepatch_bsc1144502_init(void);
static inline void livepatch_bsc1144502_cleanup(void) {}


struct pt_regs;
struct insn;

unsigned long klp_insn_get_seg_base(struct pt_regs *regs, int seg_reg_idx);
char klp_insn_get_code_seg_params(struct pt_regs *regs);
int klp_get_seg_base_limit(struct insn *insn, struct pt_regs *regs,
			   int regoff, unsigned long *base,
			   unsigned long *limit);

#else /* !IS_ENABLED(CONFIG_X86_64) */

static inline int livepatch_bsc1144502_init(void) { return 0; }

static inline void livepatch_bsc1144502_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_X86_64) */
#endif /* _LIVEPATCH_BSC1144502_H */

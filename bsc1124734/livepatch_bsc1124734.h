#ifndef _LIVEPATCH_BSC1124734_H
#define _LIVEPATCH_BSC1124734_H

#if IS_ENABLED(CONFIG_KVM_INTEL)

int livepatch_bsc1124734_init(void);
void livepatch_bsc1124734_cleanup(void);


struct vcpu_vmx;

void klp_free_nested(struct vcpu_vmx *vmx);

#else /* !IS_ENABLED(CONFIG_KVM_INTEL) */

static inline int livepatch_bsc1124734_init(void) { return 0; }

static inline void livepatch_bsc1124734_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_KVM_INTEL) */
#endif /* _LIVEPATCH_BSC1124734_H */

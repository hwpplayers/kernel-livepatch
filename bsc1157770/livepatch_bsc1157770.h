#ifndef _LIVEPATCH_BSC1157770_H
#define _LIVEPATCH_BSC1157770_H

#if IS_ENABLED(CONFIG_X86_64)

int livepatch_bsc1157770_init(void);
void livepatch_bsc1157770_cleanup(void);

#define LIVEPATCH_BSC1157770_FUNCS

#else /* !IS_ENABLED(CONFIG_X86_64) */

static inline int livepatch_bsc1157770_init(void) { return 0; }

static inline void livepatch_bsc1157770_cleanup(void) {}

#define LIVEPATCH_BSC1157770_FUNCS

#endif /* IS_ENABLED(CONFIG_X86_64) */
#endif /* _LIVEPATCH_BSC1157770_H */

#ifndef _LIVEPATCH_BSC1171254_H
#define _LIVEPATCH_BSC1171254_H

#if IS_ENABLED(CONFIG_MWIFIEX)

int livepatch_bsc1171254_init(void);
void livepatch_bsc1171254_cleanup(void);


struct mwifiex_private;

int
klpp_mwifiex_cmd_append_vsie_tlv(struct mwifiex_private *priv,
			    u16 vsie_mask, u8 **buffer);

#else /* !IS_ENABLED(CONFIG_MWIFIEX) */

static inline int livepatch_bsc1171254_init(void) { return 0; }

static inline void livepatch_bsc1171254_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_MWIFIEX) */
#endif /* _LIVEPATCH_BSC1171254_H */

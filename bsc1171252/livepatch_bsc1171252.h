#ifndef _LIVEPATCH_BSC1171252_H
#define _LIVEPATCH_BSC1171252_H

#if IS_ENABLED(CONFIG_MWIFIEX)

int livepatch_bsc1171252_init(void);
void livepatch_bsc1171252_cleanup(void);


struct mwifiex_private;
struct host_cmd_ds_command;

int klpp_mwifiex_ret_wmm_get_status(struct mwifiex_private *priv,
			       const struct host_cmd_ds_command *resp);

#else /* !IS_ENABLED(CONFIG_MWIFIEX) */

static inline int livepatch_bsc1171252_init(void) { return 0; }

static inline void livepatch_bsc1171252_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_MWIFIEX) */
#endif /* _LIVEPATCH_BSC1171252_H */

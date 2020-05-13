#ifndef _LIVEPATCH_BSC1171254_H
#define _LIVEPATCH_BSC1171254_H

int livepatch_bsc1171254_init(void);
void livepatch_bsc1171254_cleanup(void);


struct mwifiex_private;
struct host_cmd_ds_command;
struct mwifiex_user_scan_cfg;

int klpp_mwifiex_cmd_append_vsie_tlv(struct mwifiex_private *priv, u16 vsie_mask,
				u8 **buffer);

int klpp_mwifiex_cmd_802_11_bg_scan_config(struct mwifiex_private *priv,
				      struct host_cmd_ds_command *cmd,
				      void *data_buf);

int klpp_mwifiex_scan_networks(struct mwifiex_private *priv,
			  const struct mwifiex_user_scan_cfg *user_scan_in);

#endif /* _LIVEPATCH_BSC1171254_H */

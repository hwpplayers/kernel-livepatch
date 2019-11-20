#ifndef _LIVEPATCH_BSC1156334_H
#define _LIVEPATCH_BSC1156334_H

#if IS_ENABLED(CONFIG_BT_HCIUART)

int livepatch_bsc1156334_init(void);
void livepatch_bsc1156334_cleanup(void);


struct tty_struct;
struct file;

int klpp_hci_uart_tty_ioctl(struct tty_struct *tty, struct file *file,
			      unsigned int cmd, unsigned long arg);

#else /* !IS_ENABLED(CONFIG_BT_HCIUART) */

static inline int livepatch_bsc1156334_init(void) { return 0; }

static inline void livepatch_bsc1156334_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_BT_HCIUART) */
#endif /* _LIVEPATCH_BSC1156334_H */

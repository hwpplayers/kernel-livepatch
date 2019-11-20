/*
 * livepatch_bsc1156334
 *
 * Fix for CVE-2019-15917, bsc#1156334
 *
 *  Upstream commit:
 *  56897b217a1d ("Bluetooth: hci_ldisc: Postpone HCI_UART_PROTO_READY bit set
 *                 in hci_uart_set_proto()")
 *
 *  SLE12-SP1 commit:
 *  none yet
 *
 *  SLE12-SP2 and -SP3 commit:
 *  not affected
 *
 *  SLE12-SP4, SLE15 and SLE15-SP1 commit:
 *  0f69a9079d0d11fbfb46a0d13a095faa012e411f
 *
 *
 *  Copyright (c) 2019 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
 *
 *  Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#if IS_ENABLED(CONFIG_BT_HCIUART)

#if !IS_MODULE(CONFIG_BT_HCIUART)
#error "Live patch supports only CONFIG_BT_HCIUART=m"
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/tty.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/signal.h>
#include <linux/ioctl.h>
#include <linux/skbuff.h>
#include <linux/serdev.h>
#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1156334.h"
#include "../kallsyms_relocs.h"


#define LIVEPATCHED_MODULE "hci_uart"

static __printf(1, 2)
void (*klpe_bt_err)(const char *fmt, ...);


static struct hci_dev *(*klpe_hci_alloc_dev)(void);
static void (*klpe_hci_free_dev)(struct hci_dev *hdev);
static int (*klpe_hci_register_dev)(struct hci_dev *hdev);

/* from drivers/bluetooth/hci_uart.h */
#define HCIUARTSETPROTO		_IOW('U', 200, int)
#define HCIUARTGETPROTO		_IOR('U', 201, int)
#define HCIUARTGETDEVICE	_IOR('U', 202, int)
#define HCIUARTSETFLAGS		_IOW('U', 203, int)
#define HCIUARTGETFLAGS		_IOR('U', 204, int)

#define HCI_UART_MAX_PROTO	12

#define HCI_UART_RAW_DEVICE	0
#define HCI_UART_RESET_ON_INIT	1
#define HCI_UART_CREATE_AMP	2
#define HCI_UART_INIT_PENDING	3
#define HCI_UART_EXT_CONFIG	4
#define HCI_UART_VND_DETECT	5

struct hci_uart;

struct hci_uart_proto {
	unsigned int id;
	const char *name;
	unsigned int manufacturer;
	unsigned int init_speed;
	unsigned int oper_speed;
	int (*open)(struct hci_uart *hu);
	int (*close)(struct hci_uart *hu);
	int (*flush)(struct hci_uart *hu);
	int (*setup)(struct hci_uart *hu);
	int (*set_baudrate)(struct hci_uart *hu, unsigned int speed);
	int (*recv)(struct hci_uart *hu, const void *data, int len);
	int (*enqueue)(struct hci_uart *hu, struct sk_buff *skb);
	struct sk_buff *(*dequeue)(struct hci_uart *hu);
};

struct hci_uart {
	struct tty_struct	*tty;
	struct serdev_device	*serdev;
	struct hci_dev		*hdev;
	unsigned long		flags;
	unsigned long		hdev_flags;

	struct work_struct	init_ready;
	struct work_struct	write_work;

	const struct hci_uart_proto *proto;
	rwlock_t		proto_lock;	/* Stop work for proto close */
	void			*priv;

	struct sk_buff		*tx_skb;
	unsigned long		tx_state;

	unsigned int init_speed;
	unsigned int oper_speed;

	u8			alignment;
	u8			padding;
};

#define HCI_UART_PROTO_SET	0
#define HCI_UART_REGISTERED	1
#define HCI_UART_PROTO_READY	2


/* from drivers/bluetooth/hci_ldisc.c */
static const struct hci_uart_proto *(*klpe_hup)[HCI_UART_MAX_PROTO];

static const struct hci_uart_proto *klpr_hci_uart_get_proto(unsigned int id)
{
	if (id >= HCI_UART_MAX_PROTO)
		return NULL;

	return (*klpe_hup)[id];
}

static int (*klpe_hci_uart_open)(struct hci_dev *hdev);

static int (*klpe_hci_uart_flush)(struct hci_dev *hdev);

static int (*klpe_hci_uart_close)(struct hci_dev *hdev);

static int (*klpe_hci_uart_send_frame)(struct hci_dev *hdev, struct sk_buff *skb);

static int (*klpe_hci_uart_setup)(struct hci_dev *hdev);

static int klpr_hci_uart_register_dev(struct hci_uart *hu)
{
	struct hci_dev *hdev;

	BT_DBG("");

	/* Initialize and register HCI device */
	hdev = (*klpe_hci_alloc_dev)();
	if (!hdev) {
		(*klpe_bt_err)("Can't allocate HCI device" "\n");
		return -ENOMEM;
	}

	hu->hdev = hdev;

	hdev->bus = HCI_UART;
	hci_set_drvdata(hdev, hu);

	/* Only when vendor specific setup callback is provided, consider
	 * the manufacturer information valid. This avoids filling in the
	 * value for Ericsson when nothing is specified.
	 */
	if (hu->proto->setup)
		hdev->manufacturer = hu->proto->manufacturer;

	hdev->open  = (*klpe_hci_uart_open);
	hdev->close = (*klpe_hci_uart_close);
	hdev->flush = (*klpe_hci_uart_flush);
	hdev->send  = (*klpe_hci_uart_send_frame);
	hdev->setup = (*klpe_hci_uart_setup);
	SET_HCIDEV_DEV(hdev, hu->tty->dev);

	if (test_bit(HCI_UART_RAW_DEVICE, &hu->hdev_flags))
		set_bit(HCI_QUIRK_RAW_DEVICE, &hdev->quirks);

	if (test_bit(HCI_UART_EXT_CONFIG, &hu->hdev_flags))
		set_bit(HCI_QUIRK_EXTERNAL_CONFIG, &hdev->quirks);

	if (!test_bit(HCI_UART_RESET_ON_INIT, &hu->hdev_flags))
		set_bit(HCI_QUIRK_RESET_ON_CLOSE, &hdev->quirks);

	if (test_bit(HCI_UART_CREATE_AMP, &hu->hdev_flags))
		hdev->dev_type = HCI_AMP;
	else
		hdev->dev_type = HCI_PRIMARY;

	if (test_bit(HCI_UART_INIT_PENDING, &hu->hdev_flags))
		return 0;

	if ((*klpe_hci_register_dev)(hdev) < 0) {
		(*klpe_bt_err)("Can't register HCI device" "\n");
		hu->hdev = NULL;
		(*klpe_hci_free_dev)(hdev);
		return -ENODEV;
	}

	set_bit(HCI_UART_REGISTERED, &hu->flags);

	return 0;
}

/* patched, inlined */
static int klpp_hci_uart_set_proto(struct hci_uart *hu, int id)
{
	const struct hci_uart_proto *p;
	int err;

	p = klpr_hci_uart_get_proto(id);
	if (!p)
		return -EPROTONOSUPPORT;

	err = p->open(hu);
	if (err)
		return err;

	hu->proto = p;
	/*
	 * Fix CVE-2019-15917
	 *  -1 line
	 */

	err = klpr_hci_uart_register_dev(hu);
	if (err) {
		/*
		 * Fix CVE-2019-15917
		 *  -1 line
		 */
		clear_bit(HCI_UART_PROTO_READY, &hu->flags);
		p->close(hu);
		return err;
	}

	/*
	 * Fix CVE-2019-15917
	 *  +1 line
	 */
	set_bit(HCI_UART_PROTO_READY, &hu->flags);
	return 0;
}

static int hci_uart_set_flags(struct hci_uart *hu, unsigned long flags)
{
	unsigned long valid_flags = BIT(HCI_UART_RAW_DEVICE) |
				    BIT(HCI_UART_RESET_ON_INIT) |
				    BIT(HCI_UART_CREATE_AMP) |
				    BIT(HCI_UART_INIT_PENDING) |
				    BIT(HCI_UART_EXT_CONFIG) |
				    BIT(HCI_UART_VND_DETECT);

	if (flags & ~valid_flags)
		return -EINVAL;

	hu->hdev_flags = flags;

	return 0;
}

/* patched, calls inlined hci_uart_set_proto() */
int klpp_hci_uart_tty_ioctl(struct tty_struct *tty, struct file *file,
			      unsigned int cmd, unsigned long arg)
{
	struct hci_uart *hu = tty->disc_data;
	int err = 0;

	BT_DBG("");

	/* Verify the status of the device */
	if (!hu)
		return -EBADF;

	switch (cmd) {
	case HCIUARTSETPROTO:
		if (!test_and_set_bit(HCI_UART_PROTO_SET, &hu->flags)) {
			err = klpp_hci_uart_set_proto(hu, arg);
			if (err)
				clear_bit(HCI_UART_PROTO_SET, &hu->flags);
		} else
			err = -EBUSY;
		break;

	case HCIUARTGETPROTO:
		if (test_bit(HCI_UART_PROTO_SET, &hu->flags))
			err = hu->proto->id;
		else
			err = -EUNATCH;
		break;

	case HCIUARTGETDEVICE:
		if (test_bit(HCI_UART_REGISTERED, &hu->flags))
			err = hu->hdev->id;
		else
			err = -EUNATCH;
		break;

	case HCIUARTSETFLAGS:
		if (test_bit(HCI_UART_PROTO_SET, &hu->flags))
			err = -EBUSY;
		else
			err = hci_uart_set_flags(hu, arg);
		break;

	case HCIUARTGETFLAGS:
		err = hu->hdev_flags;
		break;

	default:
		err = n_tty_ioctl_helper(tty, file, cmd, arg);
		break;
	}

	return err;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "bt_err", (void *)&klpe_bt_err, "bluetooth" },
	{ "hci_alloc_dev", (void *)&klpe_hci_alloc_dev, "bluetooth" },
	{ "hci_free_dev", (void *)&klpe_hci_free_dev, "bluetooth" },
	{ "hci_register_dev", (void *)&klpe_hci_register_dev, "bluetooth" },
	{ "hup", (void *)&klpe_hup, "hci_uart" },
	{ "hci_uart_open", (void *)&klpe_hci_uart_open, "hci_uart" },
	{ "hci_uart_flush", (void *)&klpe_hci_uart_flush, "hci_uart" },
	{ "hci_uart_close", (void *)&klpe_hci_uart_close, "hci_uart" },
	{ "hci_uart_send_frame", (void *)&klpe_hci_uart_send_frame,
	  "hci_uart" },
	{ "hci_uart_setup", (void *)&klpe_hci_uart_setup, "hci_uart" },
};

static int livepatch_bsc1156334_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1156334_module_nb = {
	.notifier_call = livepatch_bsc1156334_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1156334_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1156334_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1156334_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1156334_module_nb);
}

#endif /* IS_ENABLED(CONFIG_BT_HCIUART) */

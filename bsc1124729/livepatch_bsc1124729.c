/*
 * livepatch_bsc1124729
 *
 * Fix for CVE-2019-6974, bsc#1124729
 *
 *  Upstream commit:
 *  cfa39381173d ("kvm: fix kvm_ioctl_create_device() reference counting
 *                 (CVE-2019-6974)")
 *
 *  SLE12(-SP1) commit:
 *  d56c6d72a828c35c09655ac3ed96c47e66ccc89f
 *
 *  SLE12-SP2 commit:
 *  d4c76e9456ea18aad11cc1246d550f91089bfa61
 *
 *  SLE12-SP3 commits:
 *  d4c76e9456ea18aad11cc1246d550f91089bfa61
 *  5fdcc9222f58490e8e5a46fb1c56807e90a8cc6f
 *
 *  SLE12-SP4 commit:
 *  7e4d01d69b6e979af3d7e54f1e8243565729ddd9
 *
 *  SLE15 commit:
 *  7e4d01d69b6e979af3d7e54f1e8243565729ddd9
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kvm_host.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/anon_inodes.h>
#include <linux/vmalloc.h>
#include <linux/debugfs.h>
#include "livepatch_bsc1124729.h"
#include "kallsyms_relocs.h"

#if !(IS_ENABLED(CONFIG_X86_64) && IS_MODULE(CONFIG_KVM)) &&		\
    !(IS_ENABLED(CONFIG_PPC64) && IS_MODULE(CONFIG_KVM_BOOK3S_64))
#error "Live patch supports only CONFIG_KVM=m"
#endif

#ifndef __KVM_HAVE_IRQ_LINE
#error "Live patch supports only defined(__KVM_HAVE_IRQ_LINE)"
#endif

#define LIVEPATCHED_MODULE "kvm"


static struct kvm_device_ops *(*klp_kvm_device_ops_table)[KVM_DEV_TYPE_MAX];
static struct preempt_ops (*klp_kvm_preempt_ops);
static struct file_operations (*klp_kvm_vcpu_fops);
static const struct file_operations (*klp_kvm_device_fops);

static void (*klp_kvm_get_kvm)(struct kvm *kvm);
static void (*klp_kvm_put_kvm)(struct kvm *kvm);
static struct kvm_vcpu *(*klp_kvm_arch_vcpu_create)(struct kvm *kvm,
						    unsigned int id);
static int (*klp_kvm_arch_vcpu_setup)(struct kvm_vcpu *vcpu);
static void (*klp_kvm_arch_vcpu_postcreate)(struct kvm_vcpu *vcpu);
static void (*klp_kvm_arch_vcpu_destroy)(struct kvm_vcpu *vcpu);
static bool (*klp_kvm_arch_has_vcpu_debugfs)(void);
static int (*klp_kvm_arch_create_vcpu_debugfs)(struct kvm_vcpu *vcpu);
static int
(*klp_kvm_set_memory_region)(struct kvm *kvm,
			     const struct kvm_userspace_memory_region *mem);
static int (*klp_kvm_vm_ioctl_get_dirty_log)(struct kvm *kvm,
					     struct kvm_dirty_log *log);
static int
(*klp_kvm_vm_ioctl_register_coalesced_mmio)(struct kvm *kvm,
					    struct kvm_coalesced_mmio_zone *zone);
static int
(*klp_kvm_vm_ioctl_unregister_coalesced_mmio)(struct kvm *kvm,
					      struct kvm_coalesced_mmio_zone *zone);
static int (*klp_kvm_irqfd)(struct kvm *kvm, struct kvm_irqfd *args);
static int (*klp_kvm_ioeventfd)(struct kvm *kvm, struct kvm_ioeventfd *args);

#ifdef CONFIG_HAVE_KVM_MSI
static int (*klp_kvm_send_userspace_msi)(struct kvm *kvm, struct kvm_msi *msi);
#endif

static int (*klp_kvm_vm_ioctl_irq_line)(struct kvm *kvm,
					struct kvm_irq_level *irq_level,
					bool line_status);

#ifdef CONFIG_HAVE_KVM_IRQ_ROUTING
static bool (*klp_kvm_arch_can_set_irq_routing)(struct kvm *kvm);
static int (*klp_kvm_set_irq_routing)(struct kvm *kvm,
				      const struct kvm_irq_routing_entry *ue,
				      unsigned nr,
				      unsigned flags);
#endif

static long (*klp_kvm_vm_ioctl_check_extension_generic)(struct kvm *kvm,
							long arg);
static long (*klp_kvm_arch_vm_ioctl)(struct file *filp,
				     unsigned int ioctl, unsigned long arg);

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "kvm_device_ops_table", (void *)&klp_kvm_device_ops_table, "kvm" },
	{ "kvm_preempt_ops", (void *)&klp_kvm_preempt_ops, "kvm" },
	{ "kvm_vcpu_fops", (void *)&klp_kvm_vcpu_fops, "kvm" },
	{ "kvm_device_fops", (void *)&klp_kvm_device_fops, "kvm" },
	{ "kvm_get_kvm", (void *)&klp_kvm_get_kvm, "kvm" },
	{ "kvm_put_kvm", (void *)&klp_kvm_put_kvm, "kvm" },
	{ "kvm_arch_vcpu_create", (void *)&klp_kvm_arch_vcpu_create, "kvm" },
	{ "kvm_arch_vcpu_setup", (void *)&klp_kvm_arch_vcpu_setup, "kvm" },
	{ "kvm_arch_vcpu_postcreate", (void *)&klp_kvm_arch_vcpu_postcreate,
	  "kvm" },
	{ "kvm_arch_vcpu_destroy", (void *)&klp_kvm_arch_vcpu_destroy, "kvm" },
	{ "kvm_arch_has_vcpu_debugfs", (void *)&klp_kvm_arch_has_vcpu_debugfs,
	  "kvm" },
	{ "kvm_arch_create_vcpu_debugfs",
	  (void *)&klp_kvm_arch_create_vcpu_debugfs, "kvm" },
	{ "kvm_set_memory_region", (void *)&klp_kvm_set_memory_region, "kvm" },
	{ "kvm_vm_ioctl_get_dirty_log", (void *)&klp_kvm_vm_ioctl_get_dirty_log,
	  "kvm" },
	{ "kvm_vm_ioctl_register_coalesced_mmio",
	  (void *)&klp_kvm_vm_ioctl_register_coalesced_mmio, "kvm" },
	{ "kvm_vm_ioctl_unregister_coalesced_mmio",
	  (void *)&klp_kvm_vm_ioctl_unregister_coalesced_mmio, "kvm" },
	{ "kvm_irqfd", (void *)&klp_kvm_irqfd, "kvm" },
	{ "kvm_ioeventfd", (void *)&klp_kvm_ioeventfd, "kvm" },
#ifdef CONFIG_HAVE_KVM_MSI
	{ "kvm_send_userspace_msi", (void *)&klp_kvm_send_userspace_msi,
	  "kvm" },
#endif
	{ "kvm_vm_ioctl_irq_line", (void *)&klp_kvm_vm_ioctl_irq_line,
	  "kvm" },
#ifdef CONFIG_HAVE_KVM_IRQ_ROUTING
	{ "kvm_arch_can_set_irq_routing",
	  (void *)&klp_kvm_arch_can_set_irq_routing, "kvm" },
	{ "kvm_set_irq_routing", (void *)&klp_kvm_set_irq_routing, "kvm" },
#endif
	{ "kvm_vm_ioctl_check_extension_generic",
	  (void *)&klp_kvm_vm_ioctl_check_extension_generic, "kvm" },
	{ "kvm_arch_vm_ioctl", (void *)&klp_kvm_arch_vm_ioctl, "kvm" },
};


/* from virt/kvm/kvm_main.c */
#define KLP_ITOA_MAX_LEN 12

/* inlined */
static int klp_kvm_vm_ioctl_set_memory_region(struct kvm *kvm,
					      struct kvm_userspace_memory_region *mem)
{
	if ((u16)mem->slot >= KVM_USER_MEM_SLOTS)
		return -EINVAL;

	return klp_kvm_set_memory_region(kvm, mem);
}

/* inlined */
static int klp_create_vcpu_fd(struct kvm_vcpu *vcpu)
{
	return anon_inode_getfd("kvm-vcpu", &(*klp_kvm_vcpu_fops), vcpu, O_RDWR | O_CLOEXEC);
}

/* inlined */
static int klp_kvm_create_vcpu_debugfs(struct kvm_vcpu *vcpu)
{
	char dir_name[KLP_ITOA_MAX_LEN * 2];
	int ret;

	if (!klp_kvm_arch_has_vcpu_debugfs())
		return 0;

	if (!debugfs_initialized())
		return 0;

	snprintf(dir_name, sizeof(dir_name), "vcpu%d", vcpu->vcpu_id);
	vcpu->debugfs_dentry = debugfs_create_dir(dir_name,
								vcpu->kvm->debugfs_dentry);
	if (!vcpu->debugfs_dentry)
		return -ENOMEM;

	ret = klp_kvm_arch_create_vcpu_debugfs(vcpu);
	if (ret < 0) {
		debugfs_remove_recursive(vcpu->debugfs_dentry);
		return ret;
	}

	return 0;
}

/* inlined */
static int klp_kvm_vm_ioctl_create_vcpu(struct kvm *kvm, u32 id)
{
	int r;
	struct kvm_vcpu *vcpu;

	if (id >= KVM_MAX_VCPU_ID)
		return -EINVAL;

	mutex_lock(&kvm->lock);
	if (kvm->created_vcpus == KVM_MAX_VCPUS) {
		mutex_unlock(&kvm->lock);
		return -EINVAL;
	}

	kvm->created_vcpus++;
	mutex_unlock(&kvm->lock);

	vcpu = klp_kvm_arch_vcpu_create(kvm, id);
	if (IS_ERR(vcpu)) {
		r = PTR_ERR(vcpu);
		goto vcpu_decrement;
	}

	preempt_notifier_init(&vcpu->preempt_notifier, &(*klp_kvm_preempt_ops));

	r = klp_kvm_arch_vcpu_setup(vcpu);
	if (r)
		goto vcpu_destroy;

	r = klp_kvm_create_vcpu_debugfs(vcpu);
	if (r)
		goto vcpu_destroy;

	mutex_lock(&kvm->lock);
	if (kvm_get_vcpu_by_id(kvm, id)) {
		r = -EEXIST;
		goto unlock_vcpu_destroy;
	}

	BUG_ON(kvm->vcpus[atomic_read(&kvm->online_vcpus)]);

	/* Now it's all set up, let userspace reach it */
	klp_kvm_get_kvm(kvm);
	r = klp_create_vcpu_fd(vcpu);
	if (r < 0) {
		klp_kvm_put_kvm(kvm);
		goto unlock_vcpu_destroy;
	}

	kvm->vcpus[atomic_read(&kvm->online_vcpus)] = vcpu;

	/*
	 * Pairs with smp_rmb() in kvm_get_vcpu.  Write kvm->vcpus
	 * before kvm->online_vcpu's incremented value.
	 */
	smp_wmb();
	atomic_inc(&kvm->online_vcpus);

	mutex_unlock(&kvm->lock);
	klp_kvm_arch_vcpu_postcreate(vcpu);
	return r;

unlock_vcpu_destroy:
	mutex_unlock(&kvm->lock);
	debugfs_remove_recursive(vcpu->debugfs_dentry);
vcpu_destroy:
	klp_kvm_arch_vcpu_destroy(vcpu);
vcpu_decrement:
	mutex_lock(&kvm->lock);
	kvm->created_vcpus--;
	mutex_unlock(&kvm->lock);
	return r;
}



/* patched, inlined */
static int klp_kvm_ioctl_create_device(struct kvm *kvm,
				       struct kvm_create_device *cd)
{
	struct kvm_device_ops *ops = NULL;
	struct kvm_device *dev;
	bool test = cd->flags & KVM_CREATE_DEVICE_TEST;
	int ret;

	if (cd->type >= ARRAY_SIZE((*klp_kvm_device_ops_table)))
		return -ENODEV;

	ops = (*klp_kvm_device_ops_table)[cd->type];
	if (ops == NULL)
		return -ENODEV;

	if (test)
		return 0;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->ops = ops;
	dev->kvm = kvm;

	mutex_lock(&kvm->lock);
	ret = ops->create(dev, cd->type);
	if (ret < 0) {
		mutex_unlock(&kvm->lock);
		kfree(dev);
		return ret;
	}
	list_add(&dev->vm_node, &kvm->devices);
	mutex_unlock(&kvm->lock);

	if (ops->init)
		ops->init(dev);

	/*
	 * Fix CVE-2019-6974
	 *  +1 line
	 */
	klp_kvm_get_kvm(kvm);
	ret = anon_inode_getfd(ops->name, &(*klp_kvm_device_fops), dev, O_RDWR | O_CLOEXEC);
	if (ret < 0) {
		/*
		 * Fix CVE-2019-6974
		 *  +1 line
		 */
		klp_kvm_put_kvm(kvm);
		mutex_lock(&kvm->lock);
		list_del(&dev->vm_node);
		mutex_unlock(&kvm->lock);
		ops->destroy(dev);
		return ret;
	}

	/*
	 * Fix CVE-2019-6974
	 *  -1 line
	 */
	cd->fd = ret;
	return 0;
}

/* patched, calls inlined kvm_ioctl_create_device() */
long klp_kvm_vm_ioctl(struct file *filp,
		      unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm = filp->private_data;
	void __user *argp = (void __user *)arg;
	int r;

	if (kvm->mm != current->mm)
		return -EIO;
	switch (ioctl) {
	case KVM_CREATE_VCPU:
		r = klp_kvm_vm_ioctl_create_vcpu(kvm, arg);
		break;
	case KVM_SET_USER_MEMORY_REGION: {
		struct kvm_userspace_memory_region kvm_userspace_mem;

		r = -EFAULT;
		if (copy_from_user(&kvm_userspace_mem, argp,
						sizeof(kvm_userspace_mem)))
			goto out;

		r = klp_kvm_vm_ioctl_set_memory_region(kvm, &kvm_userspace_mem);
		break;
	}
	case KVM_GET_DIRTY_LOG: {
		struct kvm_dirty_log log;

		r = -EFAULT;
		if (copy_from_user(&log, argp, sizeof(log)))
			goto out;
		r = klp_kvm_vm_ioctl_get_dirty_log(kvm, &log);
		break;
	}
#ifdef CONFIG_KVM_MMIO
	case KVM_REGISTER_COALESCED_MMIO: {
		struct kvm_coalesced_mmio_zone zone;

		r = -EFAULT;
		if (copy_from_user(&zone, argp, sizeof(zone)))
			goto out;
		r = klp_kvm_vm_ioctl_register_coalesced_mmio(kvm, &zone);
		break;
	}
	case KVM_UNREGISTER_COALESCED_MMIO: {
		struct kvm_coalesced_mmio_zone zone;

		r = -EFAULT;
		if (copy_from_user(&zone, argp, sizeof(zone)))
			goto out;
		r = klp_kvm_vm_ioctl_unregister_coalesced_mmio(kvm, &zone);
		break;
	}
#endif
	case KVM_IRQFD: {
		struct kvm_irqfd data;

		r = -EFAULT;
		if (copy_from_user(&data, argp, sizeof(data)))
			goto out;
		r = klp_kvm_irqfd(kvm, &data);
		break;
	}
	case KVM_IOEVENTFD: {
		struct kvm_ioeventfd data;

		r = -EFAULT;
		if (copy_from_user(&data, argp, sizeof(data)))
			goto out;
		r = klp_kvm_ioeventfd(kvm, &data);
		break;
	}
#ifdef CONFIG_HAVE_KVM_MSI
	case KVM_SIGNAL_MSI: {
		struct kvm_msi msi;

		r = -EFAULT;
		if (copy_from_user(&msi, argp, sizeof(msi)))
			goto out;
		r = klp_kvm_send_userspace_msi(kvm, &msi);
		break;
	}
#endif
#ifdef __KVM_HAVE_IRQ_LINE
	case KVM_IRQ_LINE_STATUS:
	case KVM_IRQ_LINE: {
		struct kvm_irq_level irq_event;

		r = -EFAULT;
		if (copy_from_user(&irq_event, argp, sizeof(irq_event)))
			goto out;

		r = klp_kvm_vm_ioctl_irq_line(kvm, &irq_event,
					ioctl == KVM_IRQ_LINE_STATUS);
		if (r)
			goto out;

		r = -EFAULT;
		if (ioctl == KVM_IRQ_LINE_STATUS) {
			if (copy_to_user(argp, &irq_event, sizeof(irq_event)))
				goto out;
		}

		r = 0;
		break;
	}
#endif
#ifdef CONFIG_HAVE_KVM_IRQ_ROUTING
	case KVM_SET_GSI_ROUTING: {
		struct kvm_irq_routing routing;
		struct kvm_irq_routing __user *urouting;
		struct kvm_irq_routing_entry *entries = NULL;

		r = -EFAULT;
		if (copy_from_user(&routing, argp, sizeof(routing)))
			goto out;
		r = -EINVAL;
		if (!klp_kvm_arch_can_set_irq_routing(kvm))
			goto out;
		if (routing.nr > KVM_MAX_IRQ_ROUTES)
			goto out;
		if (routing.flags)
			goto out;
		if (routing.nr) {
			r = -ENOMEM;
			entries = vmalloc(routing.nr * sizeof(*entries));
			if (!entries)
				goto out;
			r = -EFAULT;
			urouting = argp;
			if (copy_from_user(entries, urouting->entries,
					   routing.nr * sizeof(*entries)))
				goto out_free_irq_routing;
		}
		r = klp_kvm_set_irq_routing(kvm, entries, routing.nr,
					    routing.flags);
out_free_irq_routing:
		vfree(entries);
		break;
	}
#endif /* CONFIG_HAVE_KVM_IRQ_ROUTING */
	case KVM_CREATE_DEVICE: {
		struct kvm_create_device cd;

		r = -EFAULT;
		if (copy_from_user(&cd, argp, sizeof(cd)))
			goto out;

		r = klp_kvm_ioctl_create_device(kvm, &cd);
		if (r)
			goto out;

		r = -EFAULT;
		if (copy_to_user(argp, &cd, sizeof(cd)))
			goto out;

		r = 0;
		break;
	}
	case KVM_CHECK_EXTENSION:
		r = klp_kvm_vm_ioctl_check_extension_generic(kvm, arg);
		break;
	default:
		r = klp_kvm_arch_vm_ioctl(filp, ioctl, arg);
	}
out:
	return r;
}



static int livepatch_bsc1124729_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1124729_module_nb = {
	.notifier_call = livepatch_bsc1124729_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1124729_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1124729_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1124729_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1124729_module_nb);
}

/*
 * livepatch_bsc1124734
 *
 * Fix for CVE-2019-7221, bsc#1124734
 *
 *  Upstream commit:
 *  ecec76885bcf ("KVM: nVMX: unconditionally cancel preemption timer
 *                 in free_nested (CVE-2019-7221)")
 *
 *  SLE12(-SP1) commit:
 *  2cfc10fcb868c6205c09746afa7f037b3b9a3955
 *
 *  SLE12-SP2 commit:
 *  ff1adbba7a32004dab45ee00bb3290942c593e14
 *
 *  SLE12-SP3 commit:
 *  ff1adbba7a32004dab45ee00bb3290942c593e14
 *
 *  SLE12-SP4 commit:
 *  2b60717b20c2000bbe3cca8e324f91be217b0eeb
 *
 *  SLE15 commit:
 *  2b60717b20c2000bbe3cca8e324f91be217b0eeb
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

#if IS_ENABLED(CONFIG_KVM_INTEL)

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kvm_host.h>
#include <linux/list.h>
#include <asm/vmx.h>
#include <linux/hrtimer.h>
#include <linux/highmem.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <asm/nospec-branch.h>
#include "livepatch_bsc1124734.h"
#include "kallsyms_relocs.h"

#if !IS_MODULE(CONFIG_KVM_INTEL)
#error "Live patch supports only CONFIG_KVM_INTEL=m"
#endif

#define LIVEPATCHED_MODULE "kvm_intel"


struct vmcs;
struct loaded_vmcs;

static bool (*klp_enable_vpid);
static spinlock_t (*klp_vmx_vpid_lock);
static DECLARE_BITMAP((*klp_vmx_vpid_bitmap), VMX_NR_VPIDS);
static bool (*klp_enable_shadow_vmcs);
static struct vmcs_config (*klp_vmcs_config);

static void (*klp_vmwrite_error)(unsigned long field, unsigned long value);
static void (*klp_vmcs_clear)(struct vmcs *vmcs);
static void (*klp_free_loaded_vmcs)(struct loaded_vmcs *loaded_vmcs);

static bool (*klp_kvm_rebooting);

static asmlinkage void (*klp_kvm_spurious_fault)(void);
static void (*klp_kvm_release_page_dirty)(struct page *page);

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "enable_vpid", (void *)&klp_enable_vpid, "kvm_intel" },
	{ "vmx_vpid_lock", (void *)&klp_vmx_vpid_lock, "kvm_intel" },
	{ "vmx_vpid_bitmap", (void *)&klp_vmx_vpid_bitmap, "kvm_intel" },
	{ "enable_shadow_vmcs", (void *)&klp_enable_shadow_vmcs, "kvm_intel" },
	{ "vmcs_config", (void *)&klp_vmcs_config, "kvm_intel" },
	{ "vmwrite_error", (void *)&klp_vmwrite_error, "kvm_intel" },
	{ "vmcs_clear", (void *)&klp_vmcs_clear, "kvm_intel" },
	{ "free_loaded_vmcs", (void *)&klp_free_loaded_vmcs, "kvm_intel" },

	{ "kvm_rebooting", (void *)&klp_kvm_rebooting, "kvm" },
	{ "kvm_spurious_fault", (void *)&klp_kvm_spurious_fault, "kvm" },
	{ "kvm_release_page_dirty", (void *)&klp_kvm_release_page_dirty,
	  "kvm" },
};


/* from arch/x86/include/asm/kvm_host.h */
/*
 * Avoid module dependency on kvm.ko.
 *
 * This is the original macro but with the load from kvm_rebooting
 * replaced by an indirect load from *klp_kvm_rebooting and the call
 * to kvm_spurious_fault() replaced by an indirect call to
 * *klp_kvm_spurious_fault.
 */
#define klp____kvm_handle_fault_on_reboot(insn, cleanup_insn)	\
	"666: " insn "\n\t" \
	"668: \n\t"                           \
	".pushsection .fixup, \"ax\" \n" \
	"667: \n\t" \
	cleanup_insn "\n\t"		      \
	"pushq %%rax \n\t"		      \
	"movq klp_kvm_rebooting, %%rax\n\t"   \
	"cmpb $0, (%%rax) \n\t"	      \
	"popq %%rax \n\t"		      \
	"jne 668b \n\t"      		      \
	__ASM_SIZE(push) " $666b \n\t"	      \
	/* this depends on [thunk_target] "a" constraints */	\
	"movq klp_kvm_spurious_fault, %%rax \n\t"		\
	CALL_NOSPEC "\n\t"					\
	/* kvm_spurious_fault() is noreturn. */		\
	/* Silence objtool by balancing the stack */		\
	/* and jmp'ing somewhere */				\
	"popq %%rax\n\t"					\
	"jmp 668b \n\t"					\
	".popsection \n\t" \
	_ASM_EXTABLE(666b, 667b)

#define klp__kvm_handle_fault_on_reboot(insn)		\
	klp____kvm_handle_fault_on_reboot(insn, "")

/* from arch/x86/kvm/vmx.c */
#define klp__ex(x) klp__kvm_handle_fault_on_reboot(x)
#define klp__ex_clear(x, reg) \
	klp____kvm_handle_fault_on_reboot(x, "xor " reg " , " reg)

#define KLP_NR_AUTOLOAD_MSRS 8

struct loaded_vmcs {
	struct vmcs *vmcs;
	struct vmcs *shadow_vmcs;
	int cpu;
	bool launched;
	bool nmi_known_unmasked;
	unsigned long vmcs_host_cr3;	/* May not match real cr3 */
	unsigned long vmcs_host_cr4;	/* May not match real cr4 */
	/* Support for vnmi-less CPUs */
	int soft_vnmi_blocked;
	ktime_t entry_time;
	s64 vnmi_blocked_time;
	unsigned long *msr_bitmap;
	struct list_head loaded_vmcss_on_cpu_link;
};

struct nested_vmx {
	/* Has the level1 guest done vmxon? */
	bool vmxon;
	gpa_t vmxon_ptr;
	bool pml_full;

	/* The guest-physical address of the current VMCS L1 keeps for L2 */
	gpa_t current_vmptr;
	/*
	 * Cache of the guest's VMCS, existing outside of guest memory.
	 * Loaded from guest memory during VMPTRLD. Flushed to guest
	 * memory during VMCLEAR and VMPTRLD.
	 */
	struct vmcs12 *cached_vmcs12;
	/*
	 * Indicates if the shadow vmcs must be updated with the
	 * data hold by vmcs12
	 */
	bool sync_shadow_vmcs;

	bool change_vmcs01_virtual_x2apic_mode;
	/* L2 must run next, and mustn't decide to exit to L1. */
	bool nested_run_pending;

	struct loaded_vmcs vmcs02;

	/*
	 * Guest pages referred to in the vmcs02 with host-physical
	 * pointers, so we must keep them pinned while L2 runs.
	 */
	struct page *apic_access_page;
	struct page *virtual_apic_page;
	struct page *pi_desc_page;
	struct pi_desc *pi_desc;
	bool pi_pending;
	u16 posted_intr_nv;

	struct hrtimer preemption_timer;
	bool preemption_timer_expired;

	/* to migrate it to L2 if VM_ENTRY_LOAD_DEBUG_CONTROLS is off */
	u64 vmcs01_debugctl;

	u16 vpid02;
	u16 last_vpid;

	/*
	 * We only store the "true" versions of the VMX capability MSRs. We
	 * generate the "non-true" versions by setting the must-be-1 bits
	 * according to the SDM.
	 */
	u32 nested_vmx_procbased_ctls_low;
	u32 nested_vmx_procbased_ctls_high;
	u32 nested_vmx_secondary_ctls_low;
	u32 nested_vmx_secondary_ctls_high;
	u32 nested_vmx_pinbased_ctls_low;
	u32 nested_vmx_pinbased_ctls_high;
	u32 nested_vmx_exit_ctls_low;
	u32 nested_vmx_exit_ctls_high;
	u32 nested_vmx_entry_ctls_low;
	u32 nested_vmx_entry_ctls_high;
	u32 nested_vmx_misc_low;
	u32 nested_vmx_misc_high;
	u32 nested_vmx_ept_caps;
	u32 nested_vmx_vpid_caps;
	u64 nested_vmx_basic;
	u64 nested_vmx_cr0_fixed0;
	u64 nested_vmx_cr0_fixed1;
	u64 nested_vmx_cr4_fixed0;
	u64 nested_vmx_cr4_fixed1;
	u64 nested_vmx_vmcs_enum;
	u64 nested_vmx_vmfunc_controls;

	/* SMM related state */
	struct {
		/* in VMX operation on SMM entry? */
		bool vmxon;
		/* in guest mode on SMM entry? */
		bool guest_mode;
	} smm;
};

struct pi_desc {
	u32 pir[8];     /* Posted interrupt requested */
	union {
		struct {
				/* bit 256 - Outstanding Notification */
			u16	on	: 1,
				/* bit 257 - Suppress Notification */
				sn	: 1,
				/* bit 271:258 - Reserved */
				rsvd_1	: 14;
				/* bit 279:272 - Notification Vector */
			u8	nv;
				/* bit 287:280 - Reserved */
			u8	rsvd_2;
				/* bit 319:288 - Notification Destination */
			u32	ndst;
		};
		u64 control;
	};
	u32 rsvd[6];
} __aligned(64);

struct vmx_msrs {
	unsigned int		nr;
	struct vmx_msr_entry	val[KLP_NR_AUTOLOAD_MSRS];
};

struct vcpu_vmx {
	struct kvm_vcpu       vcpu;
	unsigned long         host_rsp;
	u8                    fail;
	u8		      msr_bitmap_mode;
	u32                   exit_intr_info;
	u32                   idt_vectoring_info;
	ulong                 rflags;
	struct shared_msr_entry *guest_msrs;
	int                   nmsrs;
	int                   save_nmsrs;
	unsigned long	      host_idt_base;
#ifdef CONFIG_X86_64
	u64 		      msr_host_kernel_gs_base;
	u64 		      msr_guest_kernel_gs_base;
#endif

	u64 		      arch_capabilities;
	u64 		      spec_ctrl;

	u32 vm_entry_controls_shadow;
	u32 vm_exit_controls_shadow;
	u32 secondary_exec_control;

	/*
	 * loaded_vmcs points to the VMCS currently used in this vcpu. For a
	 * non-nested (L1) guest, it always points to vmcs01. For a nested
	 * guest (L2), it points to a different VMCS.  loaded_cpu_state points
	 * to the VMCS whose state is loaded into the CPU registers that only
	 * need to be switched when transitioning to/from the kernel; a NULL
	 * value indicates that host state is loaded.
	 */
	struct loaded_vmcs    vmcs01;
	struct loaded_vmcs   *loaded_vmcs;
	struct loaded_vmcs   *loaded_cpu_state;
	bool                  __launched; /* temporary, used in vmx_vcpu_run */
	struct msr_autoload {
		struct vmx_msrs guest;
		struct vmx_msrs host;
	} msr_autoload;

	struct {
		u16           fs_sel, gs_sel, ldt_sel;
#ifdef CONFIG_X86_64
		u16           ds_sel, es_sel;
#endif
		int           gs_ldt_reload_needed;
		int           fs_reload_needed;
		u64           msr_host_bndcfgs;
	} host_state;
	struct {
		int vm86_active;
		ulong save_rflags;
		struct kvm_segment segs[8];
	} rmode;
	struct {
		u32 bitmask; /* 4 bits per segment (1 bit per field) */
		struct kvm_save_segment {
			u16 selector;
			unsigned long base;
			u32 limit;
			u32 ar;
		} seg[8];
	} segment_cache;
	int vpid;
	bool emulation_required;

	u32 exit_reason;

	/* Posted interrupt descriptor */
	struct pi_desc pi_desc;

	/* Support for a guest hypervisor (nested VMX) */
	struct nested_vmx nested;

	/* Dynamic PLE window. */
	int ple_window;
	bool ple_window_dirty;

	/* Support for PML */
#define PML_ENTITY_NUM		512
	struct page *pml_pg;

	/* apic deadline value in host tsc */
	u64 hv_deadline_tsc;

	u64 current_tsc_ratio;

	u32 host_pkru;

	/*
	 * Only bits masked by msr_ia32_feature_control_valid_bits can be set in
	 * msr_ia32_feature_control. FEATURE_CONTROL_LOCKED is always included
	 * in msr_ia32_feature_control_valid_bits.
	 */
	u64 msr_ia32_feature_control;
	u64 msr_ia32_feature_control_valid_bits;
};

struct vmcs_config {
	int size;
	int order;
	u32 basic_cap;
	u32 revision_id;
	u32 pin_based_exec_ctrl;
	u32 cpu_based_exec_ctrl;
	u32 cpu_based_2nd_exec_ctrl;
	u32 vmexit_ctrl;
	u32 vmentry_ctrl;
};

/* inlined */
static __always_inline void klp_vmcs_check64(unsigned long field)
{
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0,
			 "64-bit accessor invalid for 16-bit field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6001) == 0x2001,
			 "64-bit accessor invalid for 64-bit high field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x4000,
			 "64-bit accessor invalid for 32-bit field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x6000,
			 "64-bit accessor invalid for natural width field");
}

/* inlined */
static __always_inline unsigned long klp__vmcs_readl(unsigned long field)
{
	unsigned long value;

	asm volatile (klp__ex_clear(ASM_VMX_VMREAD_RDX_RAX, "%0")
		      : [thunk_target] "=a"(value) : "d"(field) : "cc");
	return value;
}

/* inlined */
static __always_inline void klp__vmcs_writel(unsigned long field, unsigned long value)
{
	u8 error;

	asm volatile (klp__ex(ASM_VMX_VMWRITE_RAX_RDX) "; setna %0"
		       : "=q"(error) : [thunk_target] "a"(value), "d"(field) : "cc");
	if (unlikely(error))
		klp_vmwrite_error(field, value);
}

/* inlined */
static __always_inline void klp_vmcs_write64(unsigned long field, u64 value)
{
	klp_vmcs_check64(field);
	klp__vmcs_writel(field, value);
#ifndef CONFIG_X86_64
	asm volatile ("");
	klp__vmcs_writel(field+1, value >> 32);
#endif
}

/* inlined */
static __always_inline void klp_vmcs_clear_bits(unsigned long field, u32 mask)
{
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x2000,
			 "vmcs_clear_bits does not support 64-bit fields");
	klp__vmcs_writel(field, klp__vmcs_readl(field) & ~mask);
}

/* inlined */
static void klp_free_vmcs(struct vmcs *vmcs)
{
	free_pages((unsigned long)vmcs, (*klp_vmcs_config).order);
}

/* inlined */
static void klp_free_vpid(int vpid)
{
	if (!(*klp_enable_vpid) || vpid == 0)
		return;
	spin_lock(&(*klp_vmx_vpid_lock));
	__clear_bit(vpid, (*klp_vmx_vpid_bitmap));
	spin_unlock(&(*klp_vmx_vpid_lock));
}

/* inliend */
static void klp_vmx_disable_shadow_vmcs(struct vcpu_vmx *vmx)
{
	klp_vmcs_clear_bits(SECONDARY_VM_EXEC_CONTROL, SECONDARY_EXEC_SHADOW_VMCS);
	klp_vmcs_write64(VMCS_LINK_POINTER, -1ull);
}


/* patched */
void klp_free_nested(struct vcpu_vmx *vmx)
{
	if (!vmx->nested.vmxon && !vmx->nested.smm.vmxon)
		return;

	/*
	 * Fix CVE-2019-7221
	 *  +1 line
	 */
	hrtimer_cancel(&vmx->nested.preemption_timer);
	vmx->nested.vmxon = false;
	vmx->nested.smm.vmxon = false;
	klp_free_vpid(vmx->nested.vpid02);
	vmx->nested.posted_intr_nv = -1;
	vmx->nested.current_vmptr = -1ull;
	if ((*klp_enable_shadow_vmcs)) {
		klp_vmx_disable_shadow_vmcs(vmx);
		klp_vmcs_clear(vmx->vmcs01.shadow_vmcs);
		klp_free_vmcs(vmx->vmcs01.shadow_vmcs);
		vmx->vmcs01.shadow_vmcs = NULL;
	}
	kfree(vmx->nested.cached_vmcs12);
	/* Unpin physical memory we referred to in the vmcs02 */
	if (vmx->nested.apic_access_page) {
		klp_kvm_release_page_dirty(vmx->nested.apic_access_page);
		vmx->nested.apic_access_page = NULL;
	}
	if (vmx->nested.virtual_apic_page) {
		klp_kvm_release_page_dirty(vmx->nested.virtual_apic_page);
		vmx->nested.virtual_apic_page = NULL;
	}
	if (vmx->nested.pi_desc_page) {
		kunmap(vmx->nested.pi_desc_page);
		klp_kvm_release_page_dirty(vmx->nested.pi_desc_page);
		vmx->nested.pi_desc_page = NULL;
		vmx->nested.pi_desc = NULL;
	}

	klp_free_loaded_vmcs(&vmx->nested.vmcs02);
}



static int livepatch_bsc1124734_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1124734_module_nb = {
	.notifier_call = livepatch_bsc1124734_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1124734_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1124734_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1124734_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1124734_module_nb);
}

#endif /* IS_ENABLED(CONFIG_KVM_INTEL) */

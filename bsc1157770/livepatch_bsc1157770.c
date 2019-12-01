/*
 * livepatch_bsc1157770
 *
 * Fix for bsc#1157770
 *
 *  Upstream commit:
 *  b23e5844dfe7 ("xen/pv: Fix a boot up hang revealed by int3 self test")
 *
 *  SLE12-SP1 commit:
 *  not affected
 *
 *  SLE12-SP2 commit
 *  b6986af08b78c961b18d20fa8541c646d925f2d5
 *
 *  SLE12-SP3 commit:
 *  7396f6d4f4c68bf73fb5e7f23ebf8586a2563b76
 *
 *  SLE12-SP4, SLE15 and SLE15-SP1 commit:
 *  bf509214b68459f202946a746abd8f4bf267577d
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

/*
 * Background + rationale
 * ----------------------
 * For XEN PV guests, the hypervisor wraps the guest's exception entry
 * handlers with its own ones. To this end, the PV guest announces its
 * entry handler addresses via certain hypercalls to the hypervisor, see
 * e.g. xen_load_idt().
 *
 * Usually, xen_load_idt() & Co would just pass the address of the
 * native handler as set in the IDT table. But it special cases on
 * those ones which are known to use ISTs in the native case and
 * substitutes non-IST variants for those.
 *
 * Even though the int3 trap handler doesn't use the IST anymore in
 * the native case since upstream commit d8ba61ba58c8 ("x86/entry/64:
 * Don't use IST entry for #BP stack"), XEN still treats it as if it
 * would and registers a substitute, xenint3(), with the hypervisor
 * instead. Until recently, int3() and xenint3() had identical
 * implementations and the XEN PV code substituting one for another
 * had simply been superfluous. Then, int3_emulate_call() support was
 * implemented and the the int3 entry code is now expected to arrange
 * for a gap on the stack. Unfortunately, the XEN PV int3 handler
 * implementation had been missed and, in consequence,
 * ftrace_int3_handler() can make XEN PV kernels crash. This affects
 * live patching, as ftrace_int3_handler() can be executed during
 * patch application (if one of the patched functions happens to be
 * invoked at certain points during the transition).
 *
 * This shall be fixed from the live patch's module_init(), i.e.
 * before the live patch itself gets applied.
 *
 * The simplest approach would be to just issue a hypercall and
 * register a XEN-compatible stub around the native int3 handler with
 * the XEN hypervisor on each CPU. However, this is not guaranteed to
 * last forever, because any load_idt() invocation would revert
 * this. One example when this happens is the loading of the tracing
 * IDT, another is loading the "debug IDT" when an NMI finds itself
 * interrupting the debug exception handler. Additionally live
 * patching xen_load_idt() to not replace the int3 handler with the
 * XEN PV implementation would not work reliably during the
 * transition. In particular not for the latter case -- doing that
 * would on the contrary only increase the probability of failure.
 *
 * Thus, the approach chosen here is to rewrite the int3 entry in XEN
 * PV's lookup table, trap_array, with the address of a XEN-compatible
 * stub around the native int3 handler and reload the IDT.
 */

#if IS_ENABLED(CONFIG_X86_64)

#if !IS_ENABLED(CONFIG_STRICT_MODULE_RWX)
#error "Live patch supports only CONFIG_STRICT_MODULE_RWX=y"
#endif


#include <linux/mm.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/cpu.h>
#include <linux/livepatch.h>
#include <asm/cacheflush.h>
#include <asm/desc.h>
#include <xen/events.h>
#include <xen/xen.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1157770.h"
#include "../kallsyms_relocs.h"
#include "../shadow.h"


static void *(*klpe_module_alloc)(unsigned long size);
static void (*klpe_module_memfree)(void *module_region);
static asmlinkage void (*klpe_int3)(void);
static int (*klpe_set_memory_ro)(unsigned long addr, int numpages);
static int (*klpe_set_memory_rw)(unsigned long addr, int numpages);

extern char klp_xen_int3_stub_templ_begin[];
extern char klp_xen_int3_stub_templ_end[];
extern char klp_xen_int3_stub_templ_jmp_reloc[];

static void *klp_prepare_xen_int3_stub(void)
{
	void *stub_text;
	unsigned long stub_size, stub_size_aligned;
	char *reloc_loc;
	unsigned long reloc_addr;
	int r;

	/*
	 * Prepare an int3 entry stub to be referenced from the XEN
	 * IDT: copy the stub template to a page and apply the
	 * relocation to the original, non-xen int3 entry handler.
	 */
	stub_size = klp_xen_int3_stub_templ_end - klp_xen_int3_stub_templ_begin;
	stub_size_aligned = PAGE_ALIGN(stub_size);

	stub_text = klpe_module_alloc(stub_size_aligned);
	if (!stub_text)
		return ERR_PTR(-ENOMEM);

	memzero_explicit(stub_text, stub_size_aligned);
	memcpy(stub_text, klp_xen_int3_stub_templ_begin, stub_size);

	/*
	 * Apply relocation at the jmp instruction to the original,
	 * non-xen int3 entry code handler.
	 */
	reloc_loc = ((char *)stub_text +
		     (klp_xen_int3_stub_templ_jmp_reloc -
		      klp_xen_int3_stub_templ_begin));
	/*
	 * RIP-relative addressing is relative to the next insn,
	 * i.e. relative to reloc_loc + sizof(int).
	 */
	reloc_addr = (unsigned long)reloc_loc + 4;
	reloc_addr = (unsigned long)klpe_int3 - reloc_addr;

	/*
	 * disp32 gets sign-extended. Check that all 32 high bits
	 * match the sign bit, i.e. bit 31. This sanity check should
	 * not trigger, because the module_alloc() from above should
	 * guarantee that stub_text is not too far away from kernel
	 * .text.
	 */
	if (((reloc_addr & (1UL << 31)) && (reloc_addr >> 32 != ~0U)) ||
		(!(reloc_addr & (1UL << 31)) && (reloc_addr >> 32 != 0U))) {
		pr_err("livepatch: relative displacement exceeds 32 bits\n");
		klpe_module_memfree(stub_text);
		return ERR_PTR(-EOVERFLOW);
	}

	WRITE_ONCE(*(unsigned int *)reloc_loc, (unsigned int)reloc_addr);
	flush_icache_range((unsigned long)stub_text,
			   (unsigned long)stub_text + stub_size_aligned);

	/*
	 * Remap the entry stub as RX, c.f. set_section_ro_nx() from
	 * the kernel/module.c
	 */
	r = klpe_set_memory_ro((unsigned long)stub_text,
			       stub_size_aligned >> PAGE_SHIFT);
	if (r) {
		klpe_module_memfree(stub_text);
		return ERR_PTR(r);
	}

	/*
	 * Note: KPTI is ineffective on XEN PV guests,
	 * c.f. pti_check_boottime_disable()
	 */

	return stub_text;
}

static void klp_free_xen_int3_stub(void *stub_text)
{
	unsigned long stub_size;
	int r;

	stub_size = klp_xen_int3_stub_templ_end - klp_xen_int3_stub_templ_begin;
	stub_size = PAGE_ALIGN(stub_size);

	r = klpe_set_memory_rw((unsigned long)stub_text,
			       stub_size >> PAGE_SHIFT);
	if (r) {
		/*
		 * This is unlikey to happen. If it does anyway, leak
		 * the memory.
		 */
		return;
	}
	klpe_module_memfree(stub_text);
}


/* from arch/x86/include/asm/desc.h */
static u32 __percpu (*klpe_debug_idt_ctr);
static struct desc_ptr (*klpe_debug_idt_descr);

static inline bool klpr_is_debug_idt_enabled(void)
{
	if (READ_ONCE(*this_cpu_ptr(klpe_debug_idt_ctr)))
		return true;

	return false;
}

static inline void klpr_load_debug_idt(void)
{
	load_idt((const struct desc_ptr *)&(*klpe_debug_idt_descr));
}


static atomic_t (*klpe_trace_idt_ctr);
static struct desc_ptr (*klpe_trace_idt_descr);

static inline bool klpr_is_trace_idt_enabled(void)
{
	if (atomic_read(&(*klpe_trace_idt_ctr)))
		return true;

	return false;
}

static inline void klpr_load_trace_idt(void)
{
	load_idt((const struct desc_ptr *)&(*klpe_trace_idt_descr));
}

static struct desc_ptr (*klpe_idt_descr);

static inline void klpr_load_current_idt(void)
{
	if (klpr_is_debug_idt_enabled())
		klpr_load_debug_idt();
	else if (klpr_is_trace_idt_enabled())
		klpr_load_trace_idt();
	else
		load_idt((const struct desc_ptr *)&(*klpe_idt_descr));
}

static void klp_load_current_idt_cpu_func(struct work_struct *w)
{
	klpr_load_current_idt();
}

static int (*klpe_schedule_on_each_cpu)(work_func_t func);


/* Fail-safe implementation of schedule_on_each_cpu(). */
static void klp_schedule_on_each_cpu_nofail(work_func_t func)
{
	int r;
	int cpu;
	struct work_struct fallback_work;

	/*
	 * schedule_on_each_cpu() can fail only with the per-CPU work
	 * struct_allocation. So it's all or nothing.
	 */
	r = klpe_schedule_on_each_cpu(func);
	if (likely(!r))
		return;

	/*
	 * It failed, process each online CPU individually by means of
	 * the on-stack fallback_work.
	 */
	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct work_struct *work = &fallback_work;

		INIT_WORK(work, func);
		schedule_work_on(cpu, work);
		flush_work(work);
	}
	put_online_cpus();
}

/* from arch/x86/xen/enlighten_pv.c */
struct trap_array_entry {
	void (*orig)(void);
	void (*xen)(void);
	bool ist_okay;
};

static void klp_rewrite_xen_trap_array_entry(struct trap_array_entry *entry,
					     unsigned long new_addr)
{
	WRITE_ONCE(entry->xen, (void (*)(void))new_addr);
}

asmlinkage void (*klpe_xen_xenint3)(void);

static int klp_verify_xen_trap_array_int3(struct trap_array_entry *entry)
{
	/*
	 * Verify that the given trap_array entry points to the original
	 * xen_xenint3().
	 */
	if (entry->orig != klpe_int3 || entry->xen != klpe_xen_xenint3) {
		pr_err("livepatch: unexpected address in XEN trap array entry");
		return -EINVAL;
	}

	return 0;
}

static struct trap_array_entry (*klpe_trap_array)[];

#define KLP_XEN_TRAP_ARRAY_INT3 1

static int klp_install_xen_int3_replacement(void *xen_int3_stub)
{
	int r;
	struct trap_array_entry *int3_entry;

	int3_entry = &(*klpe_trap_array)[KLP_XEN_TRAP_ARRAY_INT3];
	r = klp_verify_xen_trap_array_int3(int3_entry);
	if (r)
		return r;

	klp_rewrite_xen_trap_array_entry(int3_entry,
					 (unsigned long)xen_int3_stub);
	klp_schedule_on_each_cpu_nofail(klp_load_current_idt_cpu_func);

	return 0;
}

static void klp_uninstall_xen_int3_replacement(void)
{
	struct trap_array_entry *int3_entry;

	int3_entry = &(*klpe_trap_array)[KLP_XEN_TRAP_ARRAY_INT3];
	klp_rewrite_xen_trap_array_entry(int3_entry,
					 (unsigned long)klpe_xen_xenint3);
	klp_schedule_on_each_cpu_nofail(klp_load_current_idt_cpu_func);
	/*
	 * The schedule_on_each_cpu() invocation will guarantee that
	 * no task has got its $RIP in the stub entry.
	 */
}


static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "module_alloc", (void *)&klpe_module_alloc },
	{ "module_memfree", (void *)&klpe_module_memfree },
	{ "int3", (void *)&klpe_int3 },
	{ "set_memory_ro", (void *)&klpe_set_memory_ro },
	{ "set_memory_rw", (void *)&klpe_set_memory_rw },
	{ "debug_idt_ctr", (void *)&klpe_debug_idt_ctr },
	{ "debug_idt_descr", (void *)&klpe_debug_idt_descr },
	{ "trace_idt_ctr", (void *)&klpe_trace_idt_ctr },
	{ "trace_idt_descr", (void *)&klpe_trace_idt_descr },
	{ "idt_descr", (void *)&klpe_idt_descr },
	{ "schedule_on_each_cpu", (void *)&klpe_schedule_on_each_cpu },
	{ "xen_xenint3", (void *)&klpe_xen_xenint3 },
	{ "trap_array", (void *)&klpe_trap_array },
};

#define KLP_BSC1157770_SHARED_STATE_ID KLP_SHADOW_ID(1157770, 0)

/* Protected by module_mutex. */
struct klp_bsc1157770_shared_state
{
	unsigned long refcount;
	void *int3_stub_text;
	unsigned long reserved; /* in case the protocol needs to get extended */
};

struct klp_bsc1157770_shared_state *klp_bsc1157770_shared_state;

static int klp_bsc1157770_init_shared_state(void *obj,
					    void *shadow_data,
					    void *ctor_dat)
{
	memset(shadow_data, 0, sizeof(struct klp_bsc1157770_shared_state));
	return 0;
}

int livepatch_bsc1157770_init(void)
{
	int r;
	void *xen_int3_stub;

	/*
	 * The broken xen_xenint3() has only been installed for PV guests
	 * (but not for PVH guests), c.f. xen_start_kernel, the entry
	 * point for PV guests (but not PVH guests).
	 */
	if (!xen_pv_domain())
		return 0;

	r = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	if (r)
		return r;

	xen_int3_stub = klp_prepare_xen_int3_stub();
	if (IS_ERR(xen_int3_stub))
		return PTR_ERR(xen_int3_stub);

	mutex_lock(&module_mutex);
	klp_bsc1157770_shared_state =
		klp_shadow_get_or_alloc(NULL, KLP_BSC1157770_SHARED_STATE_ID,
					sizeof(*klp_bsc1157770_shared_state),
					GFP_KERNEL,
					klp_bsc1157770_init_shared_state, NULL);
	if (!klp_bsc1157770_shared_state) {
		mutex_unlock(&module_mutex);
		klp_free_xen_int3_stub(xen_int3_stub);
		return -ENOMEM;
	}

	if (!klp_bsc1157770_shared_state->refcount) {
		/*
		 * We're first, install the xen_int3 stub replacement.
		 */
		r = klp_install_xen_int3_replacement(xen_int3_stub);
		if (r) {
			klp_shadow_free(NULL, KLP_BSC1157770_SHARED_STATE_ID,
					NULL);
			mutex_unlock(&module_mutex);
			klp_free_xen_int3_stub(xen_int3_stub);
			return r;
		}
		klp_bsc1157770_shared_state->int3_stub_text = xen_int3_stub;
		xen_int3_stub = NULL;
	}
	++klp_bsc1157770_shared_state->refcount;
	mutex_unlock(&module_mutex);

	if (xen_int3_stub) {
		/* Our int3 stub had not been used. */
		klp_free_xen_int3_stub(xen_int3_stub);
	}

	return 0;
}

void livepatch_bsc1157770_cleanup(void)
{
	void *xen_int3_stub = NULL;

	/* C.f. livepatch_bsc1157770_init() */
	if (!xen_pv_domain())
		return;

	mutex_lock(&module_mutex);
	--klp_bsc1157770_shared_state->refcount;
	if (!klp_bsc1157770_shared_state->refcount) {
		klp_uninstall_xen_int3_replacement();
		xen_int3_stub = klp_bsc1157770_shared_state->int3_stub_text;
		klp_shadow_free(NULL, KLP_BSC1157770_SHARED_STATE_ID, NULL);
	}
	mutex_unlock(&module_mutex);
	if (xen_int3_stub)
		klp_free_xen_int3_stub(xen_int3_stub);
}

#endif /* IS_ENABLED(CONFIG_X86_64) */

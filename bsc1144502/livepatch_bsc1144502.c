/*
 * livepatch_bsc1144502
 *
 * Fix for CVE-2019-13233, bsc#1144502
 *
 *  Upstream commit:
 *  de9f869616dd ("x86/insn-eval: Fix use-after-free access to LDT entry")
 *
 *  SLE12-SP1 commit:
 *  not affected
 *
 *  SLE12-SP2 and -SP3 commit:
 *  not affected
 *
 *  SLE12-SP4 commit:
 *  not affected
 *
 *  SLE15 commit:
 *  not affected
 *
 *  SLE15-SP1 commit:
 *  d541dfbb361d20d789061a7a6ae4fd4166f17fb3
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

#if IS_ENABLED(CONFIG_X86_64)

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <asm/desc.h>
#include <asm/segment.h>
#include <asm/mmu_context.h>
#include <asm/ptrace.h>
#include <asm/inat.h>
#include <asm/insn-eval.h>
#include "livepatch_bsc1144502.h"
#include "kallsyms_relocs.h"

#if !IS_ENABLED(CONFIG_MODIFY_LDT_SYSCALL)
#error "Live patch supports only CONFIG_MODIFY_LDT_SYSCALL=y"
#endif

static insn_attr_t (*klp_inat_get_opcode_attribute)(insn_byte_t opcode);
static void (*klp_insn_get_prefixes)(struct insn *insn);
static void (*klp_insn_get_opcode)(struct insn *insn);

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "inat_get_opcode_attribute", (void *)&klp_inat_get_opcode_attribute },
	{ "insn_get_prefixes", (void *)&klp_insn_get_prefixes },
	{ "insn_get_opcode", (void *)&klp_insn_get_opcode },
};

/* from arch/x86/lib/insn-eval.c */
/* inlined */
static bool klp_is_string_insn(struct insn *insn)
{
	klp_insn_get_opcode(insn);

	/* All string instructions have a 1-byte opcode. */
	if (insn->opcode.nbytes != 1)
		return false;

	switch (insn->opcode.bytes[0]) {
	case 0x6c ... 0x6f:	/* INS, OUTS */
	case 0xa4 ... 0xa7:	/* MOVS, CMPS */
	case 0xaa ... 0xaf:	/* STOS, LODS, SCAS */
		return true;
	default:
		return false;
	}
}

/* inlined */
static int klp_get_seg_reg_override_idx(struct insn *insn)
{
	int idx = INAT_SEG_REG_DEFAULT;
	int num_overrides = 0, i;

	klp_insn_get_prefixes(insn);

	/* Look for any segment override prefixes. */
	for (i = 0; i < insn->prefixes.nbytes; i++) {
		insn_attr_t attr;

		attr = klp_inat_get_opcode_attribute(insn->prefixes.bytes[i]);
		switch (attr) {
		case INAT_MAKE_PREFIX(INAT_PFX_CS):
			idx = INAT_SEG_REG_CS;
			num_overrides++;
			break;
		case INAT_MAKE_PREFIX(INAT_PFX_SS):
			idx = INAT_SEG_REG_SS;
			num_overrides++;
			break;
		case INAT_MAKE_PREFIX(INAT_PFX_DS):
			idx = INAT_SEG_REG_DS;
			num_overrides++;
			break;
		case INAT_MAKE_PREFIX(INAT_PFX_ES):
			idx = INAT_SEG_REG_ES;
			num_overrides++;
			break;
		case INAT_MAKE_PREFIX(INAT_PFX_FS):
			idx = INAT_SEG_REG_FS;
			num_overrides++;
			break;
		case INAT_MAKE_PREFIX(INAT_PFX_GS):
			idx = INAT_SEG_REG_GS;
			num_overrides++;
			break;
		/* No default action needed. */
		}
	}

	/* More than one segment override prefix leads to undefined behavior. */
	if (num_overrides > 1)
		return -EINVAL;

	return idx;
}

/* inlined */
static bool klp_check_seg_overrides(struct insn *insn, int regoff)
{
	if (regoff == offsetof(struct pt_regs, di) && klp_is_string_insn(insn))
		return false;

	return true;
}

/* inlined */
static int klp_resolve_default_seg(struct insn *insn, struct pt_regs *regs,
				   int off)
{
	if (user_64bit_mode(regs))
		return INAT_SEG_REG_IGNORE;
	/*
	 * Resolve the default segment register as described in Section 3.7.4
	 * of the Intel Software Development Manual Vol. 1:
	 *
	 *  + DS for all references involving r[ABCD]X, and rSI.
	 *  + If used in a string instruction, ES for rDI. Otherwise, DS.
	 *  + AX, CX and DX are not valid register operands in 16-bit address
	 *    encodings but are valid for 32-bit and 64-bit encodings.
	 *  + -EDOM is reserved to identify for cases in which no register
	 *    is used (i.e., displacement-only addressing). Use DS.
	 *  + SS for rSP or rBP.
	 *  + CS for rIP.
	 */

	switch (off) {
	case offsetof(struct pt_regs, ax):
	case offsetof(struct pt_regs, cx):
	case offsetof(struct pt_regs, dx):
		/* Need insn to verify address size. */
		if (insn->addr_bytes == 2)
			return -EINVAL;

	case -EDOM:
	case offsetof(struct pt_regs, bx):
	case offsetof(struct pt_regs, si):
		return INAT_SEG_REG_DS;

	case offsetof(struct pt_regs, di):
		if (klp_is_string_insn(insn))
			return INAT_SEG_REG_ES;
		return INAT_SEG_REG_DS;

	case offsetof(struct pt_regs, bp):
	case offsetof(struct pt_regs, sp):
		return INAT_SEG_REG_SS;

	case offsetof(struct pt_regs, ip):
		return INAT_SEG_REG_CS;

	default:
		return -EINVAL;
	}
}

/* inlined */
static int klp_resolve_seg_reg(struct insn *insn, struct pt_regs *regs,
			       int regoff)
{
	int idx;

	/*
	 * In the unlikely event of having to resolve the segment register
	 * index for rIP, do it first. Segment override prefixes should not
	 * be used. Hence, it is not necessary to inspect the instruction,
	 * which may be invalid at this point.
	 */
	if (regoff == offsetof(struct pt_regs, ip)) {
		if (user_64bit_mode(regs))
			return INAT_SEG_REG_IGNORE;
		else
			return INAT_SEG_REG_CS;
	}

	if (!insn)
		return -EINVAL;

	if (!klp_check_seg_overrides(insn, regoff))
		return klp_resolve_default_seg(insn, regs, regoff);

	idx = klp_get_seg_reg_override_idx(insn);
	if (idx < 0)
		return idx;

	if (idx == INAT_SEG_REG_DEFAULT)
		return klp_resolve_default_seg(insn, regs, regoff);

	/*
	 * In long mode, segment override prefixes are ignored, except for
	 * overrides for FS and GS.
	 */
	if (user_64bit_mode(regs)) {
		if (idx != INAT_SEG_REG_FS &&
		    idx != INAT_SEG_REG_GS)
			idx = INAT_SEG_REG_IGNORE;
	}

	return idx;
}

/* inlined */
static short klp_get_segment_selector(struct pt_regs *regs, int seg_reg_idx)
{
#ifdef CONFIG_X86_64
	unsigned short sel;

	switch (seg_reg_idx) {
	case INAT_SEG_REG_IGNORE:
		return 0;
	case INAT_SEG_REG_CS:
		return (unsigned short)(regs->cs & 0xffff);
	case INAT_SEG_REG_SS:
		return (unsigned short)(regs->ss & 0xffff);
	case INAT_SEG_REG_DS:
		savesegment(ds, sel);
		return sel;
	case INAT_SEG_REG_ES:
		savesegment(es, sel);
		return sel;
	case INAT_SEG_REG_FS:
		savesegment(fs, sel);
		return sel;
	case INAT_SEG_REG_GS:
		savesegment(gs, sel);
		return sel;
	default:
		return -EINVAL;
	}
#else /* CONFIG_X86_32 */
	struct kernel_vm86_regs *vm86regs = (struct kernel_vm86_regs *)regs;

	if (v8086_mode(regs)) {
		switch (seg_reg_idx) {
		case INAT_SEG_REG_CS:
			return (unsigned short)(regs->cs & 0xffff);
		case INAT_SEG_REG_SS:
			return (unsigned short)(regs->ss & 0xffff);
		case INAT_SEG_REG_DS:
			return vm86regs->ds;
		case INAT_SEG_REG_ES:
			return vm86regs->es;
		case INAT_SEG_REG_FS:
			return vm86regs->fs;
		case INAT_SEG_REG_GS:
			return vm86regs->gs;
		case INAT_SEG_REG_IGNORE:
			/* fall through */
		default:
			return -EINVAL;
		}
	}

	switch (seg_reg_idx) {
	case INAT_SEG_REG_CS:
		return (unsigned short)(regs->cs & 0xffff);
	case INAT_SEG_REG_SS:
		return (unsigned short)(regs->ss & 0xffff);
	case INAT_SEG_REG_DS:
		return (unsigned short)(regs->ds & 0xffff);
	case INAT_SEG_REG_ES:
		return (unsigned short)(regs->es & 0xffff);
	case INAT_SEG_REG_FS:
		return (unsigned short)(regs->fs & 0xffff);
	case INAT_SEG_REG_GS:
		/*
		 * GS may or may not be in regs as per CONFIG_X86_32_LAZY_GS.
		 * The macro below takes care of both cases.
		 */
		return get_user_gs(regs);
	case INAT_SEG_REG_IGNORE:
		/* fall through */
	default:
		return -EINVAL;
	}
#endif /* CONFIG_X86_64 */
}



/* patched, callers also patched */
/*
 * Fix CVE-2019-13233
 *  -1 line, +1 line
 */
static bool klp_get_desc(struct desc_struct *out, unsigned short sel)
{
	struct desc_ptr gdt_desc = {0, 0};
	unsigned long desc_base;

#ifdef CONFIG_MODIFY_LDT_SYSCALL
	if ((sel & SEGMENT_TI_MASK) == SEGMENT_LDT) {
		/*
		 * Fix CVE-2019-13233
		 *  -1 line, +1 line
		 */
		bool success = false;
		struct ldt_struct *ldt;

		/* Bits [15:3] contain the index of the desired entry. */
		sel >>= 3;

		mutex_lock(&current->active_mm->context.lock);
		ldt = current->active_mm->context.ldt;
		/*
		 * Fix CVE-2019-13233
		 *  -2 lines, +4 lines
		 */
		if (ldt && sel < ldt->nr_entries) {
			*out = ldt->entries[sel];
			success = true;
		}

		mutex_unlock(&current->active_mm->context.lock);

		/*
		 * Fix CVE-2019-13233
		 *  -1 line, +1 line
		 */
		return success;
	}
#endif
	native_store_gdt(&gdt_desc);

	/*
	 * Segment descriptors have a size of 8 bytes. Thus, the index is
	 * multiplied by 8 to obtain the memory offset of the desired descriptor
	 * from the base of the GDT. As bits [15:3] of the segment selector
	 * contain the index, it can be regarded as multiplied by 8 already.
	 * All that remains is to clear bits [2:0].
	 */
	desc_base = sel & ~(SEGMENT_RPL_MASK | SEGMENT_TI_MASK);

	if (desc_base > gdt_desc.size)
		/*
		 * Fix CVE-2019-13233
		 *  -1 line, +1 line
		 */
		return false;

	/*
	 * Fix CVE-2019-13233
	 *  -1 line, +2 lines
	 */
	*out = *(struct desc_struct *)(gdt_desc.address + desc_base);
	return true;
}

/* patched */
unsigned long klp_insn_get_seg_base(struct pt_regs *regs, int seg_reg_idx)
{
	/*
	 * Fix CVE-2019-13233
	 *  -1 line, +1 line
	 */
	struct desc_struct desc;
	short sel;

	sel = klp_get_segment_selector(regs, seg_reg_idx);
	if (sel < 0)
		return -1L;

	if (v8086_mode(regs))
		/*
		 * Base is simply the segment selector shifted 4
		 * bits to the right.
		 */
		return (unsigned long)(sel << 4);

	if (user_64bit_mode(regs)) {
		/*
		 * Only FS or GS will have a base address, the rest of
		 * the segments' bases are forced to 0.
		 */
		unsigned long base;

		if (seg_reg_idx == INAT_SEG_REG_FS)
			rdmsrl(MSR_FS_BASE, base);
		else if (seg_reg_idx == INAT_SEG_REG_GS)
			/*
			 * swapgs was called at the kernel entry point. Thus,
			 * MSR_KERNEL_GS_BASE will have the user-space GS base.
			 */
			rdmsrl(MSR_KERNEL_GS_BASE, base);
		else
			base = 0;
		return base;
	}

	/* In protected mode the segment selector cannot be null. */
	if (!sel)
		return -1L;

	/*
	 * Fix CVE-2019-13233
	 *  -2 lines, +1 line
	 */
	if (!klp_get_desc(&desc, sel))
		return -1L;

	/*
	 * Fix CVE-2019-13233
	 *  -1 line, +1 line
	 */
	return get_desc_base(&desc);
}

/* patched, inlined */
static unsigned long klp_get_seg_limit(struct pt_regs *regs, int seg_reg_idx)
{
	/*
	 * Fix CVE-2019-13233
	 *  -1 line, +1 line
	 */
	struct desc_struct desc;
	unsigned long limit;
	short sel;

	sel = klp_get_segment_selector(regs, seg_reg_idx);
	if (sel < 0)
		return 0;

	if (user_64bit_mode(regs) || v8086_mode(regs))
		return -1L;

	if (!sel)
		return 0;

	/*
	 * Fix CVE-2019-13233
	 *  -2 lines, +1 line
	 */
	if (!klp_get_desc(&desc, sel))
		return 0;

	/*
	 * If the granularity bit is set, the limit is given in multiples
	 * of 4096. This also means that the 12 least significant bits are
	 * not tested when checking the segment limits. In practice,
	 * this means that the segment ends in (limit << 12) + 0xfff.
	 */
	/*
	 * Fix CVE-2019-13233
	 *  -2 line, +2 lines
	 */
	limit = get_desc_limit(&desc);
	if (desc.g)
		limit = (limit << 12) + 0xfff;

	return limit;
}

/* patched */
char klp_insn_get_code_seg_params(struct pt_regs *regs)
{
	/*
	 * Fix CVE-2019-13233
	 *  -1 line, +1 line
	 */
	struct desc_struct desc;
	short sel;

	if (v8086_mode(regs))
		/* Address and operand size are both 16-bit. */
		return INSN_CODE_SEG_PARAMS(2, 2);

	sel = klp_get_segment_selector(regs, INAT_SEG_REG_CS);
	if (sel < 0)
		return sel;

	/*
	 * Fix CVE-2019-13233
	 *  -2 lines, +1 line
	 */
	if (!klp_get_desc(&desc, sel))
		return -EINVAL;

	/*
	 * The most significant byte of the Type field of the segment descriptor
	 * determines whether a segment contains data or code. If this is a data
	 * segment, return error.
	 */
	/*
	 * Fix CVE-2019-13233
	 *  -1 line, +1 line
	 */
	if (!(desc.type & BIT(3)))
		return -EINVAL;

	/*
	 * Fix CVE-2019-13233
	 *  -1 line, +1 line
	 */
	switch ((desc.l << 1) | desc.d) {
	case 0: /*
		 * Legacy mode. CS.L=0, CS.D=0. Address and operand size are
		 * both 16-bit.
		 */
		return INSN_CODE_SEG_PARAMS(2, 2);
	case 1: /*
		 * Legacy mode. CS.L=0, CS.D=1. Address and operand size are
		 * both 32-bit.
		 */
		return INSN_CODE_SEG_PARAMS(4, 4);
	case 2: /*
		 * IA-32e 64-bit mode. CS.L=1, CS.D=0. Address size is 64-bit;
		 * operand size is 32-bit.
		 */
		return INSN_CODE_SEG_PARAMS(4, 8);
	case 3: /* Invalid setting. CS.L=1, CS.D=1 */
		/* fall through */
	default:
		return -EINVAL;
	}
}

/* patched, calls inlined get_seg_limit() */
int klp_get_seg_base_limit(struct insn *insn, struct pt_regs *regs,
			   int regoff, unsigned long *base,
			   unsigned long *limit)
{
	int seg_reg_idx;

	if (!base)
		return -EINVAL;

	seg_reg_idx = klp_resolve_seg_reg(insn, regs, regoff);
	if (seg_reg_idx < 0)
		return seg_reg_idx;

	*base = klp_insn_get_seg_base(regs, seg_reg_idx);
	if (*base == -1L)
		return -EINVAL;

	if (!limit)
		return 0;

	*limit = klp_get_seg_limit(regs, seg_reg_idx);
	if (!(*limit))
		return -EINVAL;

	return 0;
}



int livepatch_bsc1144502_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

#endif /* IS_ENABLED(CONFIG_X86_64) */

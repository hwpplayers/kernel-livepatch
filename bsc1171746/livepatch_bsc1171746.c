/*
 * livepatch_bsc1171746
 *
 * Fix for CVE-2018-1000199, bsc#1171746
 *
 *  Upstream commit:
 *  f67b15037a7a ("perf/hwbp: Simplify the perf-hwbp code, fix documentation")
 *
 *  SLE12-SP1 commit:
 *  not affected
 *
 *  SLE12-SP2 commit:
 *  2314608356a29db2befb3b257850065210b091e4
 *
 *  SLE12-SP3 commit:
 *  d5ffd3248b4feeff780e90c521527e6e6eb04c1b ("Linux 4.4.127")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  5b1d03420610a2c44736830c20a81cf9012793a0
 *
 *
 *  Copyright (c) 2020 SUSE
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

#if IS_ENABLED(CONFIG_HAVE_HW_BREAKPOINT)

#if !IS_ENABLED(CONFIG_PERF_EVENTS)
#error "Livepatch supports only CONFIG_PERF_EVENTS=y"
#endif

#include <linux/irqflags.h>
#include <linux/errno.h>
#include <linux/notifier.h>
#include <linux/kprobes.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/hw_breakpoint.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1171746.h"
#include "../kallsyms_relocs.h"


/* from include/linux/perf_event.h */
static void (*klpe_perf_event_disable_local)(struct perf_event *event);


/* from kernel/events/hw_breakpoint.c */
static int (*klpe_validate_hw_breakpoint)(struct perf_event *bp);

int klpp_modify_user_hw_breakpoint(struct perf_event *bp, struct perf_event_attr *attr)
{
	/*
	 * Fix CVE-2018-1000199
	 *  -5 lines
	 */
	/*
	 * modify_user_hw_breakpoint can be invoked with IRQs disabled and hence it
	 * will not be possible to raise IPIs that invoke __perf_event_disable.
	 * So call the function directly after making sure we are targeting the
	 * current task.
	 */
	if (irqs_disabled() && bp->ctx && bp->ctx->task == current)
		(*klpe_perf_event_disable_local)(bp);
	else
		perf_event_disable(bp);

	bp->attr.bp_addr = attr->bp_addr;
	bp->attr.bp_type = attr->bp_type;
	bp->attr.bp_len = attr->bp_len;
	/*
	 * Fix CVE-2018-1000199
	 *  +1 line
	 */
	bp->attr.disabled = 1;

	/*
	 * Fix CVE-2018-1000199
	 *  -19 lines, +9 lines
	 */
	if (!attr->disabled) {
		int err = (*klpe_validate_hw_breakpoint)(bp);

		if (err)
			return err;

		perf_event_enable(bp);
		bp->attr.disabled = 0;
	}

	return 0;
}


static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "perf_event_disable_local", (void *)&klpe_perf_event_disable_local },
	{ "validate_hw_breakpoint", (void *)&klpe_validate_hw_breakpoint },
};

int livepatch_bsc1171746_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

#endif /* IS_ENABLED(CONFIG_HAVE_HW_BREAKPOINT) */

/*
 * livepatch_bsc1156321
 *
 * Fix for CVE-2019-13272, bsc#1156321
 *
 *  Upstream commit:
 *  6994eefb0053 ("ptrace: Fix ->ptracer_cred handling for PTRACE_TRACEME")
 *
 *  SLE12-SP1 commit:
 *  not affected
 *
 *  SLE12-SP2 and -SP3 commit:
 *  744203f9e77b12526c1cf6fe13231602a730dd4a
 *
 *  SLE12-SP4, SLE15 and SLE15-SP1 commit:
 *  efed5b271d3b282c4447d93de93c64ad7c9dbaaf
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

#include <linux/capability.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/sched/coredump.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/ptrace.h>
#include <linux/signal.h>
#include <linux/audit.h>
#include <linux/pid_namespace.h>
#include <linux/uaccess.h>
#include <linux/sched/signal.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1156321.h"
#include "../kallsyms_relocs.h"


static rwlock_t (*klpe_tasklist_lock);

static bool (*klpe_task_set_jobctl_pending)(struct task_struct *task, unsigned long mask);

static void (*klpe_signal_wake_up_state)(struct task_struct *t, unsigned int state);


#ifdef CONFIG_SECURITY

static int (*klpe_security_ptrace_traceme)(struct task_struct *parent);

#else /* CONFIG_SECURITY */
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_SECURITY */


#ifdef CONFIG_AUDITSYSCALL

static void (*klpe___audit_ptrace)(struct task_struct *t);

static inline void klpr_audit_ptrace(struct task_struct *t)
{
	if (unlikely(!audit_dummy_context()))
		(*klpe___audit_ptrace)(t);
}

#else /* CONFIG_AUDITSYSCALL */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_AUDITSYSCALL */


#ifdef CONFIG_PROC_EVENTS

static void (*klpe_proc_ptrace_connector)(struct task_struct *task, int which_id);

#else
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_PROC_EVENTS */


/* from kernel/ptrace.c */
static void (*klpe___ptrace_link)(struct task_struct *child, struct task_struct *new_parent,
		   const struct cred *ptracer_cred);

/* patched, inlined */
static void klpp_ptrace_link(struct task_struct *child, struct task_struct *new_parent)
{
	/*
	 * Fix CVE-2019-13272
	 *  -3 lines, +1 line
	 */
	(*klpe___ptrace_link)(child, new_parent, current_cred());
}

static int (*klpe___ptrace_may_access)(struct task_struct *task, unsigned int mode);

/* patched, calls inlined ptrace_link */
int klpp_ptrace_attach(struct task_struct *task, long request,
			 unsigned long addr,
			 unsigned long flags)
{
	bool seize = (request == PTRACE_SEIZE);
	int retval;

	retval = -EIO;
	if (seize) {
		if (addr != 0)
			goto out;
		if (flags & ~(unsigned long)PTRACE_O_MASK)
			goto out;
		flags = PT_PTRACED | PT_SEIZED | (flags << PT_OPT_FLAG_SHIFT);
	} else {
		flags = PT_PTRACED;
	}

	klpr_audit_ptrace(task);

	retval = -EPERM;
	if (unlikely(task->flags & PF_KTHREAD))
		goto out;
	if (same_thread_group(task, current))
		goto out;

	/*
	 * Protect exec's credential calculations against our interference;
	 * SUID, SGID and LSM creds get determined differently
	 * under ptrace.
	 */
	retval = -ERESTARTNOINTR;
	if (mutex_lock_interruptible(&task->signal->cred_guard_mutex))
		goto out;

	task_lock(task);
	retval = (*klpe___ptrace_may_access)(task, PTRACE_MODE_ATTACH_REALCREDS);
	task_unlock(task);
	if (retval)
		goto unlock_creds;

	write_lock_irq(&(*klpe_tasklist_lock));
	retval = -EPERM;
	if (unlikely(task->exit_state))
		goto unlock_tasklist;
	if (task->ptrace)
		goto unlock_tasklist;

	if (seize)
		flags |= PT_SEIZED;
	task->ptrace = flags;

	klpp_ptrace_link(task, current);

	/* SEIZE doesn't trap tracee on attach */
	if (!seize)
		send_sig_info(SIGSTOP, SEND_SIG_FORCED, task);

	spin_lock(&task->sighand->siglock);

	/*
	 * If the task is already STOPPED, set JOBCTL_TRAP_STOP and
	 * TRAPPING, and kick it so that it transits to TRACED.  TRAPPING
	 * will be cleared if the child completes the transition or any
	 * event which clears the group stop states happens.  We'll wait
	 * for the transition to complete before returning from this
	 * function.
	 *
	 * This hides STOPPED -> RUNNING -> TRACED transition from the
	 * attaching thread but a different thread in the same group can
	 * still observe the transient RUNNING state.  IOW, if another
	 * thread's WNOHANG wait(2) on the stopped tracee races against
	 * ATTACH, the wait(2) may fail due to the transient RUNNING.
	 *
	 * The following task_is_stopped() test is safe as both transitions
	 * in and out of STOPPED are protected by siglock.
	 */
	if (task_is_stopped(task) &&
	    (*klpe_task_set_jobctl_pending)(task, JOBCTL_TRAP_STOP | JOBCTL_TRAPPING))
		(*klpe_signal_wake_up_state)(task, __TASK_STOPPED);

	spin_unlock(&task->sighand->siglock);

	retval = 0;
unlock_tasklist:
	write_unlock_irq(&(*klpe_tasklist_lock));
unlock_creds:
	mutex_unlock(&task->signal->cred_guard_mutex);
out:
	if (!retval) {
		/*
		 * We do not bother to change retval or clear JOBCTL_TRAPPING
		 * if wait_on_bit() was interrupted by SIGKILL. The tracer will
		 * not return to user-mode, it will exit and clear this bit in
		 * __ptrace_unlink() if it wasn't already cleared by the tracee;
		 * and until then nobody can ptrace this task.
		 */
		wait_on_bit(&task->jobctl, JOBCTL_TRAPPING_BIT, TASK_KILLABLE);
		(*klpe_proc_ptrace_connector)(task, PTRACE_ATTACH);
	}

	return retval;
}

/* patched, calls inlined ptrace_link */
int klpp_ptrace_traceme(void)
{
	int ret = -EPERM;

	write_lock_irq(&(*klpe_tasklist_lock));
	/* Are we already being traced? */
	if (!current->ptrace) {
		ret = (*klpe_security_ptrace_traceme)(current->parent);
		/*
		 * Check PF_EXITING to ensure ->real_parent has not passed
		 * exit_ptrace(). Otherwise we don't report the error but
		 * pretend ->real_parent untraces us right after return.
		 */
		if (!ret && !(current->real_parent->flags & PF_EXITING)) {
			current->ptrace = PT_PTRACED;
			klpp_ptrace_link(current, current->real_parent);
		}
	}
	write_unlock_irq(&(*klpe_tasklist_lock));

	return ret;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "tasklist_lock", (void *)&klpe_tasklist_lock },
	{ "task_set_jobctl_pending", (void *)&klpe_task_set_jobctl_pending },
	{ "signal_wake_up_state", (void *)&klpe_signal_wake_up_state },
	{ "security_ptrace_traceme", (void *)&klpe_security_ptrace_traceme },
	{ "__audit_ptrace", (void *)&klpe___audit_ptrace },
	{ "proc_ptrace_connector", (void *)&klpe_proc_ptrace_connector },
	{ "__ptrace_link", (void *)&klpe___ptrace_link },
	{ "__ptrace_may_access", (void *)&klpe___ptrace_may_access },
};

int livepatch_bsc1156321_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

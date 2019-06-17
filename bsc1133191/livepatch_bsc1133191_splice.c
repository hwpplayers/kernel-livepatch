/*
 * livepatch_bsc1133191_splice
 *
 * Fix for CVE-2019-11487, bsc#1133191 (fs/splice.c part)
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
#include <linux/pipe_fs_i.h>
#include <linux/splice.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include "livepatch_bsc1133191_splice.h"
#include "livepatch_bsc1133191_mm.h"
#include "kallsyms_relocs.h"

static void (*klp_orig_buffer_pipe_buf_get)(struct pipe_inode_info *pipe,
					    struct pipe_buffer *buf);
static void (*klp_pipe_wait)(struct pipe_inode_info *pipe);
static void (*klp_pipe_double_lock)(struct pipe_inode_info *pipe1,
				    struct pipe_inode_info *pipe2);
static void (*klp_wakeup_pipe_readers)(struct pipe_inode_info *pipe);
static void (*klp_wakeup_pipe_writers)(struct pipe_inode_info *pipe);
static struct pipe_inode_info *(*klp_get_pipe_info)(struct file *file);
static int (*klp_rw_verify_area)(int read_write, struct file *file,
				 const loff_t *ppos, size_t count);
static ssize_t (*klp_default_file_splice_write)(struct pipe_inode_info *pipe,
						struct file *out, loff_t *ppos,
						size_t len, unsigned int flags);
static long (*klp_do_splice_to)(struct file *in, loff_t *ppos,
				struct pipe_inode_info *pipe, size_t len,
				unsigned int flags);
static int (*klp_wait_for_space)(struct pipe_inode_info *pipe, unsigned flags);

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "buffer_pipe_buf_get", (void *)&klp_orig_buffer_pipe_buf_get },
	{ "pipe_wait", (void *)&klp_pipe_wait },
	{ "pipe_double_lock", (void *)&klp_pipe_double_lock },
	{ "wakeup_pipe_readers", (void *)&klp_wakeup_pipe_readers },
	{ "wakeup_pipe_writers", (void *)&klp_wakeup_pipe_writers },
	{ "get_pipe_info", (void *)&klp_get_pipe_info },
	{ "rw_verify_area", (void *)&klp_rw_verify_area },
	{ "default_file_splice_write", (void *)&klp_default_file_splice_write },
	{ "do_splice_to", (void *)&klp_do_splice_to },
	{ "wait_for_space", (void *)&klp_wait_for_space },
};


/* from kernel/trace/trace.c */
struct buffer_ref {
	struct ring_buffer	*buffer;
	void			*page;
	int			cpu;
	int			ref;
};


/* from fs/splice.c */
/* inlined */
static long klp_do_splice_from(struct pipe_inode_info *pipe, struct file *out,
			       loff_t *ppos, size_t len, unsigned int flags)
{
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *,
				loff_t *, size_t, unsigned int);

	if (out->f_op->splice_write)
		splice_write = out->f_op->splice_write;
	else
		splice_write = klp_default_file_splice_write;

	return splice_write(pipe, out, ppos, len, flags);
}

/* inlined */
static int klp_ipipe_prep(struct pipe_inode_info *pipe, unsigned int flags)
{
	int ret;

	/*
	 * Check ->nrbufs without the inode lock first. This function
	 * is speculative anyways, so missing one is ok.
	 */
	if (pipe->nrbufs)
		return 0;

	ret = 0;
	pipe_lock(pipe);

	while (!pipe->nrbufs) {
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}
		if (!pipe->writers)
			break;
		if (!pipe->waiting_writers) {
			if (flags & SPLICE_F_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}
		}
		klp_pipe_wait(pipe);
	}

	pipe_unlock(pipe);
	return ret;
}

/* inlined */
static int klp_opipe_prep(struct pipe_inode_info *pipe, unsigned int flags)
{
	int ret;

	/*
	 * Check ->nrbufs without the inode lock first. This function
	 * is speculative anyways, so missing one is ok.
	 */
	if (pipe->nrbufs < pipe->buffers)
		return 0;

	ret = 0;
	pipe_lock(pipe);

	while (pipe->nrbufs >= pipe->buffers) {
		if (!pipe->readers) {
			send_sig(SIGPIPE, current, 0);
			ret = -EPIPE;
			break;
		}
		if (flags & SPLICE_F_NONBLOCK) {
			ret = -EAGAIN;
			break;
		}
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}
		pipe->waiting_writers++;
		klp_pipe_wait(pipe);
		pipe->waiting_writers--;
	}

	pipe_unlock(pipe);
	return ret;
}



/* patched, prototype changed, see klp_pipe_buf_get() below */
/*
 * Fix CVE-2019-11487
 *  -1 line, +1 line
 */
static bool klp_generic_pipe_buf_get(struct pipe_inode_info *pipe,
				     struct pipe_buffer *buf)
{
	/*
	 * Fix CVE-2019-11487
	 *  -1 line, +1 line
	 */
	return klp_try_get_page(buf->page);
}

/* patched, prototype changed, see klp_pipe_buf_get() below */
/*
 * Fix CVE-2019-11487
 *  -1 line, +1 line
 */
static bool klp_buffer_pipe_buf_get(struct pipe_inode_info *pipe,
				    struct pipe_buffer *buf)
{
	struct buffer_ref *ref = (struct buffer_ref *)buf->private;

	/*
	 * Fix CVE-2019-11487
	 *  +3 lines
	 */
	if (ref->ref > INT_MAX/2)
		return false;

	ref->ref++;
	/*
	 * Fix CVE-2019-11487
	 *  +1 line
	 */
	return true;
}

/* New */
bool klp_pipe_buf_get(struct pipe_inode_info *pipe, struct pipe_buffer *buf)
{
	/*
	 * The upstream (and kernel-source) fix changes the prototype
	 * of struct pipe_buf_operations' ->get() member to return a
	 * bool rather than nothing (void). Unfortunately, we can't
	 * rely on the per-task consistency model because of
	 * bsc#1099658 and thus, live patching functions with a
	 * prototype change would potentially be risky.
	 *
	 * From an ABI perspective, it might still be safe to live
	 * patch this change directly: on e.g. x86_64 %rax is
	 * clobbered anyway, but there's also ppc64le and I don't want
	 * to rely on low-level ABI details here.
	 *
	 * Exploit the facts that
	 * - all relevant calls, i.e. those evaluating the return value,
	 *   are routed through this new pipe_buf_get() here and that
	 * - pipe_buf_operations' ->get() member only ever takes one of two
	 *   values: it's either set to generic_pipe_buf_get() or to
	 *   buffer_pipe_get().
	 *
	 * Compare the ->get() pointer against these two addresses and
	 * demultiplex to the patched implementation accordingly.
	 */
	const struct pipe_buf_operations *ops = buf->ops;

	if (ops->get == generic_pipe_buf_get) {
		return klp_generic_pipe_buf_get(pipe, buf);

	} else if (ops->get == klp_orig_buffer_pipe_buf_get) {
		return klp_buffer_pipe_buf_get(pipe, buf);

	} else {
		/*
		 * It shoud be impossible to end up here, but be
		 * conservative: call the original function and return
		 * true for indicating success.
		 */
		ops->get(pipe, buf);
		return true;
	}
}

/* patched, inlined */
static int klp_splice_pipe_to_pipe(struct pipe_inode_info *ipipe,
				   struct pipe_inode_info *opipe,
				   size_t len, unsigned int flags)
{
	struct pipe_buffer *ibuf, *obuf;
	int ret = 0, nbuf;
	bool input_wakeup = false;


retry:
	ret = klp_ipipe_prep(ipipe, flags);
	if (ret)
		return ret;

	ret = klp_opipe_prep(opipe, flags);
	if (ret)
		return ret;

	/*
	 * Potential ABBA deadlock, work around it by ordering lock
	 * grabbing by pipe info address. Otherwise two different processes
	 * could deadlock (one doing tee from A -> B, the other from B -> A).
	 */
	klp_pipe_double_lock(ipipe, opipe);

	do {
		if (!opipe->readers) {
			send_sig(SIGPIPE, current, 0);
			if (!ret)
				ret = -EPIPE;
			break;
		}

		if (!ipipe->nrbufs && !ipipe->writers)
			break;

		/*
		 * Cannot make any progress, because either the input
		 * pipe is empty or the output pipe is full.
		 */
		if (!ipipe->nrbufs || opipe->nrbufs >= opipe->buffers) {
			/* Already processed some buffers, break */
			if (ret)
				break;

			if (flags & SPLICE_F_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}

			/*
			 * We raced with another reader/writer and haven't
			 * managed to process any buffers.  A zero return
			 * value means EOF, so retry instead.
			 */
			pipe_unlock(ipipe);
			pipe_unlock(opipe);
			goto retry;
		}

		ibuf = ipipe->bufs + ipipe->curbuf;
		nbuf = (opipe->curbuf + opipe->nrbufs) & (opipe->buffers - 1);
		obuf = opipe->bufs + nbuf;

		if (len >= ibuf->len) {
			/*
			 * Simply move the whole buffer from ipipe to opipe
			 */
			*obuf = *ibuf;
			ibuf->ops = NULL;
			opipe->nrbufs++;
			ipipe->curbuf = (ipipe->curbuf + 1) & (ipipe->buffers - 1);
			ipipe->nrbufs--;
			input_wakeup = true;
		} else {
			/*
			 * Get a reference to this pipe buffer,
			 * so we can copy the contents over.
			 */
			/*
			 * Fix CVE-2019-11487
			 *  -1 line, +5 lines
			 */
			if (!klp_pipe_buf_get(ipipe, ibuf)) {
				if (ret == 0)
					ret = -EFAULT;
				break;
			}
			*obuf = *ibuf;

			/*
			 * Don't inherit the gift flag, we need to
			 * prevent multiple steals of this page.
			 */
			obuf->flags &= ~PIPE_BUF_FLAG_GIFT;

			obuf->len = len;
			opipe->nrbufs++;
			ibuf->offset += obuf->len;
			ibuf->len -= obuf->len;
		}
		ret += obuf->len;
		len -= obuf->len;
	} while (len);

	pipe_unlock(ipipe);
	pipe_unlock(opipe);

	/*
	 * If we put data in the output pipe, wakeup any potential readers.
	 */
	if (ret > 0)
		klp_wakeup_pipe_readers(opipe);

	if (input_wakeup)
		klp_wakeup_pipe_writers(ipipe);

	return ret;
}

/* patched, inlined, calls inlined splice_pipe_to_pipe() */
static long klp_do_splice(struct file *in, loff_t __user *off_in,
			  struct file *out, loff_t __user *off_out,
			  size_t len, unsigned int flags)
{
	struct pipe_inode_info *ipipe;
	struct pipe_inode_info *opipe;
	loff_t offset;
	long ret;

	ipipe = klp_get_pipe_info(in);
	opipe = klp_get_pipe_info(out);

	if (ipipe && opipe) {
		if (off_in || off_out)
			return -ESPIPE;

		if (!(in->f_mode & FMODE_READ))
			return -EBADF;

		if (!(out->f_mode & FMODE_WRITE))
			return -EBADF;

		/* Splicing to self would be fun, but... */
		if (ipipe == opipe)
			return -EINVAL;

		return klp_splice_pipe_to_pipe(ipipe, opipe, len, flags);
	}

	if (ipipe) {
		if (off_in)
			return -ESPIPE;
		if (off_out) {
			if (!(out->f_mode & FMODE_PWRITE))
				return -EINVAL;
			if (copy_from_user(&offset, off_out, sizeof(loff_t)))
				return -EFAULT;
		} else {
			offset = out->f_pos;
		}

		if (unlikely(!(out->f_mode & FMODE_WRITE)))
			return -EBADF;

		if (unlikely(out->f_flags & O_APPEND))
			return -EINVAL;

		ret = klp_rw_verify_area(WRITE, out, &offset, len);
		if (unlikely(ret < 0))
			return ret;

		file_start_write(out);
		ret = klp_do_splice_from(ipipe, out, &offset, len, flags);
		file_end_write(out);

		if (!off_out)
			out->f_pos = offset;
		else if (copy_to_user(off_out, &offset, sizeof(loff_t)))
			ret = -EFAULT;

		return ret;
	}

	if (opipe) {
		if (off_out)
			return -ESPIPE;
		if (off_in) {
			if (!(in->f_mode & FMODE_PREAD))
				return -EINVAL;
			if (copy_from_user(&offset, off_in, sizeof(loff_t)))
				return -EFAULT;
		} else {
			offset = in->f_pos;
		}

		pipe_lock(opipe);
		ret = klp_wait_for_space(opipe, flags);
		if (!ret)
			ret = klp_do_splice_to(in, &offset, opipe, len, flags);
		pipe_unlock(opipe);
		if (ret > 0)
			klp_wakeup_pipe_readers(opipe);
		if (!off_in)
			in->f_pos = offset;
		else if (copy_to_user(off_in, &offset, sizeof(loff_t)))
			ret = -EFAULT;

		return ret;
	}

	return -EINVAL;
}

/* patched, calls inlined do_splice() */
__SYSCALL_DEFINEx(6, _klp_splice, int, fd_in, loff_t __user *, off_in,
		  int, fd_out, loff_t __user *, off_out,
		  size_t, len, unsigned int, flags)
{
	struct fd in, out;
	long error;

	if (unlikely(!len))
		return 0;

	if (unlikely(flags & ~SPLICE_F_ALL))
		return -EINVAL;

	error = -EBADF;
	in = fdget(fd_in);
	if (in.file) {
		if (in.file->f_mode & FMODE_READ) {
			out = fdget(fd_out);
			if (out.file) {
				if (out.file->f_mode & FMODE_WRITE)
					error = klp_do_splice(in.file, off_in,
							      out.file, off_out,
							      len, flags);
				fdput(out);
			}
		}
		fdput(in);
	}
	return error;
}

/* patched, inlined */
static int klp_link_pipe(struct pipe_inode_info *ipipe,
			 struct pipe_inode_info *opipe,
			 size_t len, unsigned int flags)
{
	struct pipe_buffer *ibuf, *obuf;
	int ret = 0, i = 0, nbuf;

	/*
	 * Potential ABBA deadlock, work around it by ordering lock
	 * grabbing by pipe info address. Otherwise two different processes
	 * could deadlock (one doing tee from A -> B, the other from B -> A).
	 */
	klp_pipe_double_lock(ipipe, opipe);

	do {
		if (!opipe->readers) {
			send_sig(SIGPIPE, current, 0);
			if (!ret)
				ret = -EPIPE;
			break;
		}

		/*
		 * If we have iterated all input buffers or ran out of
		 * output room, break.
		 */
		if (i >= ipipe->nrbufs || opipe->nrbufs >= opipe->buffers)
			break;

		ibuf = ipipe->bufs + ((ipipe->curbuf + i) & (ipipe->buffers-1));
		nbuf = (opipe->curbuf + opipe->nrbufs) & (opipe->buffers - 1);

		/*
		 * Get a reference to this pipe buffer,
		 * so we can copy the contents over.
		 */
		/*
		 * Fix CVE-2019-11487
		 *  -1 line, +5 lines
		 */
		if (!klp_pipe_buf_get(ipipe, ibuf)) {
			if (ret == 0)
				ret = -EFAULT;
			break;
		}

		obuf = opipe->bufs + nbuf;
		*obuf = *ibuf;

		/*
		 * Don't inherit the gift flag, we need to
		 * prevent multiple steals of this page.
		 */
		obuf->flags &= ~PIPE_BUF_FLAG_GIFT;

		if (obuf->len > len)
			obuf->len = len;

		opipe->nrbufs++;
		ret += obuf->len;
		len -= obuf->len;
		i++;
	} while (len);

	/*
	 * return EAGAIN if we have the potential of some data in the
	 * future, otherwise just return 0
	 */
	if (!ret && ipipe->waiting_writers && (flags & SPLICE_F_NONBLOCK))
		ret = -EAGAIN;

	pipe_unlock(ipipe);
	pipe_unlock(opipe);

	/*
	 * If we put data in the output pipe, wakeup any potential readers.
	 */
	if (ret > 0)
		klp_wakeup_pipe_readers(opipe);

	return ret;
}

/* patched, inlined, calls inlined link_pipe() */
static long klp_do_tee(struct file *in, struct file *out, size_t len,
		   unsigned int flags)
{
	struct pipe_inode_info *ipipe = klp_get_pipe_info(in);
	struct pipe_inode_info *opipe = klp_get_pipe_info(out);
	int ret = -EINVAL;

	/*
	 * Duplicate the contents of ipipe to opipe without actually
	 * copying the data.
	 */
	if (ipipe && opipe && ipipe != opipe) {
		/*
		 * Keep going, unless we encounter an error. The ipipe/opipe
		 * ordering doesn't really matter.
		 */
		ret = klp_ipipe_prep(ipipe, flags);
		if (!ret) {
			ret = klp_opipe_prep(opipe, flags);
			if (!ret)
				ret = klp_link_pipe(ipipe, opipe, len, flags);
		}
	}

	return ret;
}

/* patched, calls inlined do_tee() */
__SYSCALL_DEFINEx(4, _klp_tee, int, fdin, int, fdout, size_t, len, unsigned int, flags)
{
	struct fd in;
	int error;

	if (unlikely(flags & ~SPLICE_F_ALL))
		return -EINVAL;

	if (unlikely(!len))
		return 0;

	error = -EBADF;
	in = fdget(fdin);
	if (in.file) {
		if (in.file->f_mode & FMODE_READ) {
			struct fd out = fdget(fdout);
			if (out.file) {
				if (out.file->f_mode & FMODE_WRITE)
					error = klp_do_tee(in.file, out.file,
							   len, flags);
				fdput(out);
			}
		}
 		fdput(in);
 	}

	return error;
}


int livepatch_bsc1133191_splice_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

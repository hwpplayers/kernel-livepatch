/*
 * livepatch_bsc1133191_fuse
 *
 * Fix for CVE-2019-11487, bsc#1133191 (fuse.ko part)
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
#include <linux/slab.h>
#include "livepatch_bsc1133191_fuse.h"
#include "livepatch_bsc1133191_splice.h"
#include "kallsyms_relocs.h"

#if !IS_MODULE(CONFIG_FUSE_FS)
#error "Live patch supports only CONFIG_FUSE_FS=m"
#endif

#define LIVEPATCHED_MODULE "fuse"

struct fuse_dev;
struct fuse_copy_state;

static ssize_t (*klp_fuse_dev_do_write)(struct fuse_dev *fud,
					struct fuse_copy_state *cs,
					size_t nbytes);

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "fuse_dev_do_write", (void *)&klp_fuse_dev_do_write, "fuse" },
};


/* from fs/fuse/dev.c */
/* inlined */
static struct fuse_dev *klp_fuse_get_dev(struct file *file)
{
	/*
	 * Lockless access is OK, because file->private data is set
	 * once during mount and is valid until the file is released.
	 */
	return READ_ONCE(file->private_data);
}

struct fuse_copy_state {
	int write;
	struct fuse_req *req;
	struct iov_iter *iter;
	struct pipe_buffer *pipebufs;
	struct pipe_buffer *currbuf;
	struct pipe_inode_info *pipe;
	unsigned long nr_segs;
	struct page *pg;
	unsigned len;
	unsigned offset;
	unsigned move_pages:1;
};

/* inlined */
static void klp_fuse_copy_init(struct fuse_copy_state *cs, int write,
			       struct iov_iter *iter)
{
	memset(cs, 0, sizeof(*cs));
	cs->write = write;
	cs->iter = iter;
}



/* patched */
ssize_t klp_fuse_dev_splice_write(struct pipe_inode_info *pipe,
				  struct file *out, loff_t *ppos,
				  size_t len, unsigned int flags)
{
	unsigned nbuf;
	unsigned idx;
	struct pipe_buffer *bufs;
	struct fuse_copy_state cs;
	struct fuse_dev *fud;
	size_t rem;
	ssize_t ret;

	fud = klp_fuse_get_dev(out);
	if (!fud)
		return -EPERM;

	pipe_lock(pipe);

	bufs = kmalloc(pipe->buffers * sizeof(struct pipe_buffer), GFP_KERNEL);
	if (!bufs) {
		pipe_unlock(pipe);
		return -ENOMEM;
	}

	nbuf = 0;
	rem = 0;
	for (idx = 0; idx < pipe->nrbufs && rem < len; idx++)
		rem += pipe->bufs[(pipe->curbuf + idx) & (pipe->buffers - 1)].len;

	ret = -EINVAL;
	if (rem < len) {
		/*
		 * Fix CVE-2019-11487
		 *  -2 lines, +1 line
		 */
		goto out_free;
	}

	rem = len;
	while (rem) {
		struct pipe_buffer *ibuf;
		struct pipe_buffer *obuf;

		BUG_ON(nbuf >= pipe->buffers);
		BUG_ON(!pipe->nrbufs);
		ibuf = &pipe->bufs[pipe->curbuf];
		obuf = &bufs[nbuf];

		if (rem >= ibuf->len) {
			*obuf = *ibuf;
			ibuf->ops = NULL;
			pipe->curbuf = (pipe->curbuf + 1) & (pipe->buffers - 1);
			pipe->nrbufs--;
		} else {
			/*
			 * Fix CVE-2019-11487
			 *  -1 line, +3 lines
			 */
			if (!klp_pipe_buf_get(pipe, ibuf))
				goto out_free;

			*obuf = *ibuf;
			obuf->flags &= ~PIPE_BUF_FLAG_GIFT;
			obuf->len = rem;
			ibuf->offset += obuf->len;
			ibuf->len -= obuf->len;
		}
		nbuf++;
		rem -= obuf->len;
	}
	pipe_unlock(pipe);

	klp_fuse_copy_init(&cs, 0, NULL);
	cs.pipebufs = bufs;
	cs.nr_segs = nbuf;
	cs.pipe = pipe;

	if (flags & SPLICE_F_MOVE)
		cs.move_pages = 1;

	ret = klp_fuse_dev_do_write(fud, &cs, len);

	/*
	 * Fix CVE-2019-11487
	 *  +2 lines
	 */
	pipe_lock(pipe);
out_free:
	for (idx = 0; idx < nbuf; idx++)
		pipe_buf_release(pipe, &bufs[idx]);
	/*
	 * Fix CVE-2019-11487
	 *  +1 line
	 */
	pipe_unlock(pipe);

	/*
	 * Fix CVE-2019-11487
	 *  -1 line
	 */
	kfree(bufs);
	return ret;
}



static int livepatch_bsc1133191_fuse_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1133191_fuse_module_nb = {
	.notifier_call = livepatch_bsc1133191_fuse_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1133191_fuse_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1133191_fuse_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1133191_fuse_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1133191_fuse_module_nb);
}

/*
 * livepatch_bsc1156320
 *
 * Fix for CVE-2018-16871, bsc#1156320
 *
 *  Upstream commit:
 *  01310bb7c9c9 ("nfsd: COPY and CLONE operations require the saved filehandle
 *                 to be set")
 *
 *  SLE12-SP1 commit:
 *  not affected
 *
 *  SLE12-SP2 and -SP3 commit:
 *  not affected
 *
 *  SLE12-SP4, SLE15 and SLE15-SP1 commit:
 *  93067d96afcc80869a94c634ec63f0e1bf7c1942
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

#include <linux/fs_struct.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/sunrpc/svc.h>
#include <linux/idr.h>
#include <uapi/linux/nfsd/nfsfh.h>
#include <linux/types.h>
#include <linux/nfs.h>
#include <linux/nfs2.h>
#include <linux/nfs3.h>
#include <linux/nfs4.h>
#include <linux/sunrpc/svc.h>
#include <linux/sunrpc/msg_prot.h>
#include <uapi/linux/nfsd/debug.h>
#include <uapi/linux/nfsd/stats.h>
#include <linux/sunrpc/cache.h>
#include <uapi/linux/nfsd/export.h>
#include <linux/nfs4.h>
#include <net/net_namespace.h>
#include <linux/sunrpc/debug.h>

#ifdef CONFIG_NFSD_V4

#include <linux/nfsd/export.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_NFSD_V4 */


#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1156320.h"
#include "../kallsyms_relocs.h"

#if !IS_MODULE(CONFIG_NFSD)
#error "Live patch supports only CONFIG_NFSD=m"
#endif

#define LIVEPATCHED_MODULE "nfsd"


/* from include/linux/sunrpc/debug.h */
#if IS_ENABLED(CONFIG_SUNRPC_DEBUG)

static unsigned int		(*klpe_nfsd_debug);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif


/* from fs/nfsd/nfsfh.h */
struct svc_fh {
	struct knfsd_fh		fh_handle;	/* FH data */
	int			fh_maxsize;	/* max size for fh_handle */
	struct dentry *		fh_dentry;	/* validated dentry */
	struct svc_export *	fh_export;	/* export pointer */

	bool			fh_locked;	/* inode locked by us */
	bool			fh_want_write;	/* remount protection taken */

#ifdef CONFIG_NFSD_V3
	bool			fh_post_saved;	/* post-op attrs saved */
	bool			fh_pre_saved;	/* pre-op attrs saved */

	/* Pre-op attributes saved during fh_lock */
	__u64			fh_pre_size;	/* size before operation */
	struct timespec		fh_pre_mtime;	/* mtime before oper */
	struct timespec		fh_pre_ctime;	/* ctime before oper */
	/*
	 * pre-op nfsv4 change attr: note must check IS_I_VERSION(inode)
	 *  to find out if it is valid.
	 */
	u64			fh_pre_change;

	/* Post-op attributes saved in fh_unlock */
	struct kstat		fh_post_attr;	/* full attrs after operation */
	u64			fh_post_change; /* nfsv4 change; see above */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_NFSD_V3 */
};


/* from fs/nfsd/state.h */
typedef struct {
	u32             cl_boot;
	u32             cl_id;
} clientid_t;

typedef struct {
	clientid_t	so_clid;
	u32		so_id;
} stateid_opaque_t;

typedef struct ____klp_stateid {
	u32                     si_generation;
	stateid_opaque_t        si_opaque;
} stateid_t;

#define RD_STATE	        0x00000010
#define WR_STATE	        0x00000020

struct nfsd4_compound_state;

static __be32 (*klpe_nfs4_preprocess_stateid_op)(struct svc_rqst *rqstp,
		struct nfsd4_compound_state *cstate, struct svc_fh *fhp,
		stateid_t *stateid, int flags, struct file **filp, bool *tmp_file);


/* from fs/nfsd/nfsd.h */
/* resolve reference to nfsd_debug */
#undef ifdebug
# define ifdebug(flag)           if ((*klpe_nfsd_debug) & NFSDDBG_##flag)

#define	nfserr_nofilehandle	cpu_to_be32(NFSERR_NOFILEHANDLE)
#define nfserr_wrong_type		cpu_to_be32(NFS4ERR_WRONG_TYPE)


/* from fs/nfsd/xdr4.h */
struct nfsd4_compound_state {
	struct svc_fh		current_fh;
	struct svc_fh		save_fh;
	struct nfs4_stateowner	*replay_owner;
	struct nfs4_client	*clp;
	/* For sessions DRC */
	struct nfsd4_session	*session;
	struct nfsd4_slot	*slot;
	int			data_offset;
	bool                    spo_must_allowed;
	size_t			iovlen;
	u32			minorversion;
	__be32			status;
	stateid_t	current_stateid;
	stateid_t	save_stateid;
	/* to indicate current and saved state id presents */
	u32		sid_flags;
};



/* from fs/nfsd/nfs4proc.c */
#define NFSDDBG_FACILITY		NFSDDBG_PROC

__be32
klpp_nfsd4_verify_copy(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
		  stateid_t *src_stateid, struct file **src,
		  stateid_t *dst_stateid, struct file **dst)
{
	__be32 status;

	/*
	 * Fix CVE-2018-16871
	 *  +3 lines
	 */
	if (!cstate->save_fh.fh_dentry)
				return nfserr_nofilehandle;

	status = (*klpe_nfs4_preprocess_stateid_op)(rqstp, cstate, &cstate->save_fh,
					    src_stateid, RD_STATE, src, NULL);
	if (status) {
		dprintk("NFSD: %s: couldn't process src stateid!\n", __func__);
		goto out;
	}

	status = (*klpe_nfs4_preprocess_stateid_op)(rqstp, cstate, &cstate->current_fh,
					    dst_stateid, WR_STATE, dst, NULL);
	if (status) {
		dprintk("NFSD: %s: couldn't process dst stateid!\n", __func__);
		goto out_put_src;
	}

	/* fix up for NFS-specific error code */
	if (!S_ISREG(file_inode(*src)->i_mode) ||
	    !S_ISREG(file_inode(*dst)->i_mode)) {
		status = nfserr_wrong_type;
		goto out_put_dst;
	}

out:
	return status;
out_put_dst:
	fput(*dst);
out_put_src:
	fput(*src);
	goto out;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nfsd_debug", (void *)&klpe_nfsd_debug, "sunrpc" },
	{ "nfs4_preprocess_stateid_op",
	  (void *)&klpe_nfs4_preprocess_stateid_op, "nfsd" },
};

static int livepatch_bsc1156320_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1156320_module_nb = {
	.notifier_call = livepatch_bsc1156320_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1156320_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1156320_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1156320_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1156320_module_nb);
}

/*
 * livepatch_bsc1133191
 *
 * Fix for CVE-2019-11487, bsc#1133191
 *
 *  Upstream commits:
 *  f958d7b528 ("mm: make page ref count overflow check tighter and more
 *               explicit")
 *  88b1a17dfc ("mm: add 'try_get_page()' helper function")
 *  8fde12ca79 ("mm: prevent get_user_pages() from overflowing page refcount")
 *  15fab63e1e ("fs: prevent page refcount overflow in pipe_buf_get")
 *
 *  SLE12 + SLE12-SP1 commits:
 *  d6db1d75fc6dcb57c91f005187c7195ee6b78e74
 *  d231982412da36cd69a02ea766b353697947745d
 *  c4300e17ee99aee8e9559f40ac3e4b9479fa896b
 *  8bc7f5a46b62478f6286ec513f6f96d2a861bdc5
 *  73e5582839c75073837601f250f0f10d1296e863
 *  6381c17f403ebebe14c0d341ce961e6987f36a6a
 *  0b78a63400b313c60b9537a9ce07b487543c9eaf
 *
 *  SLE12-SP2 + SLE12-SP3 commits:
 *  1e669a5dc5fb06b5ff631714850ac90318b0fdac
 *  f4e682c1fb7576d5dc775be17ceea731651384ef
 *  3f043dc6b1078b87e1d54cf57d8e2176a4cdc4ed
 *  c79727f6f6165755c6fd518d13b928d127a4637b
 *  1cc5587aa1fa719a02a01f4eebcdfac114502ed4
 *  9e7e8285cccfedf0f23051ed8a3ab857b5863be2
 *  7432f62918150e9685d5d3d5eaaf021d3586941f
 *  84e5bdc09e7128c59b0d539ee4c9f58f238b6a7e
 *  c069670a0c72f6117c3bfca96687af9cb0396225
 *
 *  SLE12-SP4 + SLE15 + SLE15-SP1 commits:
 *  a4548d768f549230f4a54e7ceac4e7fd12e1a492
 *  2aa1b48d6d0efdf89ff016a6dfeb38141870565f
 *  f56f8d5352de335d9804fd59f90ea663e2ea8398
 *  a93915182bba01aaa77c11e9d241e480e1770712
 *  3ccf631e8c6953f3a9866572ba8b0d2659202434
 *  c6248adbf6bbbe4ef0b7c604abe84c6ed8e026d0
 *  398d9959a01029285451a7c9bfe3ca1858e3296d
 *  1a7767edfb8233a6d2b14cb78274afa9d8ac6e36
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
#include "livepatch_bsc1133191.h"

int livepatch_bsc1133191_init(void)
{
	int ret;

	ret = livepatch_bsc1133191_generic_gup_init();
	if (ret)
		goto err_generic_gup_init;

	ret = livepatch_bsc1133191_x86_gup_init();
	if (ret)
		goto err_x86_gup_init;

	ret = livepatch_bsc1133191_splice_init();
	if (ret)
		goto err_splice_init;

	ret = livepatch_bsc1133191_fuse_init();
	if (ret)
		goto err_fuse_init;

	return 0;

err_fuse_init:
	livepatch_bsc1133191_splice_cleanup();
err_splice_init:
	livepatch_bsc1133191_x86_gup_cleanup();
err_x86_gup_init:
	livepatch_bsc1133191_generic_gup_cleanup();
err_generic_gup_init:
	return ret;
}

void livepatch_bsc1133191_cleanup(void)
{
	livepatch_bsc1133191_fuse_cleanup();
	livepatch_bsc1133191_splice_cleanup();
	livepatch_bsc1133191_x86_gup_cleanup();
	livepatch_bsc1133191_generic_gup_cleanup();
}

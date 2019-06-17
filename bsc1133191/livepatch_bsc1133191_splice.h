#ifndef _LIVEPATCH_BSC1133191_SPLICE_H
#define _LIVEPATCH_BSC1133191_SPLICE_H

int livepatch_bsc1133191_splice_init(void);
static inline void livepatch_bsc1133191_splice_cleanup(void) {}

asmlinkage long SyS_klp_splice(long fd_in, long off_in,
			       long fd_out, long off_out,
			       long len, long flags);

asmlinkage long SyS_klp_tee(long fdin, long fdout, long len,
			    long flags);


struct pipe_inode_info;
struct pipe_buffer;

/* Needed by the fuse live patch part. */
bool klp_pipe_buf_get(struct pipe_inode_info *pipe, struct pipe_buffer *buf);

#endif /* _LIVEPATCH_BSC1133191_SPLICE_H */

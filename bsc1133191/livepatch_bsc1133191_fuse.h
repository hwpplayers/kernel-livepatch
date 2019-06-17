#ifndef _LIVEPATCH_BSC1133191_FUSE_H
#define _LIVEPATCH_BSC1133191_FUSE_H

int livepatch_bsc1133191_fuse_init(void);
void livepatch_bsc1133191_fuse_cleanup(void);


struct pipe_inode_info;
struct file;

ssize_t klp_fuse_dev_splice_write(struct pipe_inode_info *pipe,
				  struct file *out, loff_t *ppos,
				  size_t len, unsigned int flags);

#endif /* _LIVEPATCH_BSC1133191_FUSE_H */

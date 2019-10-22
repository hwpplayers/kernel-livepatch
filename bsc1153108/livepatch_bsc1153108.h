#ifndef _LIVEPATCH_BSC1153108_H
#define _LIVEPATCH_BSC1153108_H

static inline int livepatch_bsc1153108_init(void) { return 0; }
static inline void livepatch_bsc1153108_cleanup(void) {}


struct dir_context;

int klpp_filldir(struct dir_context *ctx, const char *name, int namlen,
		 loff_t offset, u64 ino, unsigned int d_type);

int klpp_filldir64(struct dir_context *ctx, const char *name, int namlen,
		   loff_t offset, u64 ino, unsigned int d_type);

#endif /* _LIVEPATCH_BSC1153108_H */

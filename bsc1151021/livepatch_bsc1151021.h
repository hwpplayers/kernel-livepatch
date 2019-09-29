#ifndef _LIVEPATCH_BSC1151021_H
#define _LIVEPATCH_BSC1151021_H

#include <uapi/linux/uio.h>

int livepatch_bsc1151021_init(void);
void livepatch_bsc1151021_cleanup(void);


struct vhost_virtqueue;
struct vhost_log;

int klpp_vhost_get_vq_desc(struct vhost_virtqueue *vq,
		      struct iovec iov[], unsigned int iov_size,
		      unsigned int *out_num, unsigned int *in_num,
		      struct vhost_log *log, unsigned int *log_num);

#endif /* _LIVEPATCH_BSC1151021_H */

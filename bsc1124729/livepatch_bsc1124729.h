#ifndef _LIVEPATCH_BSC1124729_H
#define _LIVEPATCH_BSC1124729_H

int livepatch_bsc1124729_init(void);
void livepatch_bsc1124729_cleanup(void);


struct file;

long klp_kvm_vm_ioctl(struct file *filp,
		      unsigned int ioctl, unsigned long arg);

#endif /* _LIVEPATCH_BSC1124729_H */

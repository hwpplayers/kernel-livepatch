#ifndef _LIVEPATCH_BSC1135280_H
#define _LIVEPATCH_BSC1135280_H

#if IS_ENABLED(CONFIG_DRM_I915_GVT_KVMGT)

int livepatch_bsc1135280_init(void);
void livepatch_bsc1135280_cleanup(void);

struct mdev_device;
struct vm_area_struct;

int klp_intel_vgpu_mmap(struct mdev_device *mdev, struct vm_area_struct *vma);


#else /* !IS_ENABLED(CONFIG_DRM_I915_GVT_KVMGT) */

static inline int livepatch_bsc1135280_init(void) { return 0; }

static inline void livepatch_bsc1135280_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_DRM_I915_GVT_KVMGT) */
#endif /* _LIVEPATCH_BSC1135280_H */

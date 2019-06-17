/*
 * livepatch_bsc1135280
 *
 * Fix for CVE-2019-11085, bsc#1135280
 *
 *  Upstream commit:
 *  51b00d8509dc ("drm/i915/gvt: Fix mmap range check")
 *
 *  SLE12(-SP1) commit:
 *  not affected
 *
 *  SLE12-SP2 commit:
 *  not affected
 *
 *  SLE12-SP3 commit:
 *  not affected
 *
 *  SLE12-SP4 commits:
 *  fc802aa9ca4043004f582d78235815548696fd5c
 *  c9240fa1e8ac9db8ccb4686f074cbc4ba9e008fe
 *
 *  SLE15 commits:
 *  fc802aa9ca4043004f582d78235815548696fd5c
 *  c9240fa1e8ac9db8ccb4686f074cbc4ba9e008fe
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

#if IS_ENABLED(CONFIG_DRM_I915_GVT_KVMGT)

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/uuid.h>
#include <linux/mdev.h>
#include <linux/bitmap.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/atomic.h>
#include <linux/rbtree.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/workqueue.h>
#include <linux/vfio.h>
#include <linux/idr.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/ioport.h>
#include <linux/i2c.h>
#include <linux/i2c-algo-bit.h>
#include <linux/pm_qos.h>
#include <linux/ratelimit.h>
#include <linux/sysfs.h>
#include <linux/io-mapping.h>
#include <linux/kref.h>
#include <linux/pagevec.h>
#include <linux/hrtimer.h>
#include <linux/shrinker.h>
#include <drm/drm_mm.h>
#include <drm/drmP.h>
#include <drm/drm_atomic.h>
#include <drm/drm_crtc.h>
#include <uapi/linux/pci_regs.h>
#include "livepatch_bsc1135280.h"
#include "kallsyms_relocs.h"

#if !IS_MODULE(CONFIG_DRM_I915_GVT_KVMGT)
#error "Live patch supports only CONFIG_DRM_I915_GVT_KVMGT=m"
#endif

#if !IS_MODULE(CONFIG_VFIO_MDEV)
#error "Live patch supports only CONFIG_VFIO_MDEV=m"
#endif

#if IS_ENABLED(CONFIG_DRM_I915_SELFTEST)
#error "Live patch supports only CONFIG_DRM_I915_SELFTEST=n"
#endif

#define LIVEPATCHED_MODULE "kvmgt"


static void *(*klp_mdev_get_drvdata)(struct mdev_device *mdev);

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "mdev_get_drvdata", (void *)&klp_mdev_get_drvdata, "mdev" },
};


/* from drivers/gpu/drm/i915/i915_selftest.h */
#define KLP_I915_SELFTEST_DECLARE(x)


/* from drivers/gpu/drm/i915/i915_gem.h */
#define KLP_I915_NUM_ENGINES 5


/* from drivers/gpu/drm/i915/intel_display.h */
enum pipe {
	INVALID_PIPE = -1,

	PIPE_A = 0,
	PIPE_B,
	PIPE_C,
	_PIPE_EDP,

	I915_MAX_PIPES = _PIPE_EDP
};

enum transcoder {
	TRANSCODER_A = 0,
	TRANSCODER_B,
	TRANSCODER_C,
	TRANSCODER_EDP,
	TRANSCODER_DSI_A,
	TRANSCODER_DSI_C,

	I915_MAX_TRANSCODERS
};

enum i9xx_plane_id {
	PLANE_A,
	PLANE_B,
	PLANE_C,
};

enum plane_id {
	PLANE_PRIMARY,
	PLANE_SPRITE0,
	PLANE_SPRITE1,
	PLANE_SPRITE2,
	PLANE_CURSOR,

	I915_MAX_PLANES,
};

enum port {
	PORT_NONE = -1,

	PORT_A = 0,
	PORT_B,
	PORT_C,
	PORT_D,
	PORT_E,
	PORT_F,

	I915_MAX_PORTS
};

#define KLP_I915_NUM_PHYS_VLV 2

enum intel_display_power_domain {
	POWER_DOMAIN_PIPE_A,
	POWER_DOMAIN_PIPE_B,
	POWER_DOMAIN_PIPE_C,
	POWER_DOMAIN_PIPE_A_PANEL_FITTER,
	POWER_DOMAIN_PIPE_B_PANEL_FITTER,
	POWER_DOMAIN_PIPE_C_PANEL_FITTER,
	POWER_DOMAIN_TRANSCODER_A,
	POWER_DOMAIN_TRANSCODER_B,
	POWER_DOMAIN_TRANSCODER_C,
	POWER_DOMAIN_TRANSCODER_EDP,
	POWER_DOMAIN_TRANSCODER_DSI_A,
	POWER_DOMAIN_TRANSCODER_DSI_C,
	POWER_DOMAIN_PORT_DDI_A_LANES,
	POWER_DOMAIN_PORT_DDI_B_LANES,
	POWER_DOMAIN_PORT_DDI_C_LANES,
	POWER_DOMAIN_PORT_DDI_D_LANES,
	POWER_DOMAIN_PORT_DDI_E_LANES,
	POWER_DOMAIN_PORT_DDI_F_LANES,
	POWER_DOMAIN_PORT_DDI_A_IO,
	POWER_DOMAIN_PORT_DDI_B_IO,
	POWER_DOMAIN_PORT_DDI_C_IO,
	POWER_DOMAIN_PORT_DDI_D_IO,
	POWER_DOMAIN_PORT_DDI_E_IO,
	POWER_DOMAIN_PORT_DDI_F_IO,
	POWER_DOMAIN_PORT_DSI,
	POWER_DOMAIN_PORT_CRT,
	POWER_DOMAIN_PORT_OTHER,
	POWER_DOMAIN_VGA,
	POWER_DOMAIN_AUDIO,
	POWER_DOMAIN_PLLS,
	POWER_DOMAIN_AUX_A,
	POWER_DOMAIN_AUX_B,
	POWER_DOMAIN_AUX_C,
	POWER_DOMAIN_AUX_D,
	POWER_DOMAIN_AUX_F,
	POWER_DOMAIN_GMBUS,
	POWER_DOMAIN_MODESET,
	POWER_DOMAIN_GT_IRQ,
	POWER_DOMAIN_INIT,

	POWER_DOMAIN_NUM,
};


/* from drivers/gpu/drm/i915/intel_device_info.h */
enum intel_platform {
	INTEL_PLATFORM_UNINITIALIZED = 0,
	/* gen2 */
	INTEL_I830,
	INTEL_I845G,
	INTEL_I85X,
	INTEL_I865G,
	/* gen3 */
	INTEL_I915G,
	INTEL_I915GM,
	INTEL_I945G,
	INTEL_I945GM,
	INTEL_G33,
	INTEL_PINEVIEW,
	/* gen4 */
	INTEL_I965G,
	INTEL_I965GM,
	INTEL_G45,
	INTEL_GM45,
	/* gen5 */
	INTEL_IRONLAKE,
	/* gen6 */
	INTEL_SANDYBRIDGE,
	/* gen7 */
	INTEL_IVYBRIDGE,
	INTEL_VALLEYVIEW,
	INTEL_HASWELL,
	/* gen8 */
	INTEL_BROADWELL,
	INTEL_CHERRYVIEW,
	/* gen9 */
	INTEL_SKYLAKE,
	INTEL_BROXTON,
	INTEL_KABYLAKE,
	INTEL_GEMINILAKE,
	INTEL_COFFEELAKE,
	/* gen10 */
	INTEL_CANNONLAKE,
	INTEL_MAX_PLATFORMS
};

#define KLP_DEV_INFO_FOR_EACH_FLAG(func) \
	func(is_mobile); \
	func(is_lp); \
	func(is_alpha_support); \
	/* Keep has_* in alphabetical order */ \
	func(has_64bit_reloc); \
	func(has_aliasing_ppgtt); \
	func(has_csr); \
	func(has_ddi); \
	func(has_dp_mst); \
	func(has_reset_engine); \
	func(has_fbc); \
	func(has_fpga_dbg); \
	func(has_full_ppgtt); \
	func(has_full_48bit_ppgtt); \
	func(has_gmch_display); \
	func(has_guc); \
	func(has_guc_ct); \
	func(has_hotplug); \
	func(has_l3_dpf); \
	func(has_llc); \
	func(has_logical_ring_contexts); \
	func(has_logical_ring_preemption); \
	func(has_overlay); \
	func(has_pooled_eu); \
	func(has_psr); \
	func(has_rc6); \
	func(has_rc6p); \
	func(has_resource_streamer); \
	func(has_runtime_pm); \
	func(has_snoop); \
	func(unfenced_needs_alignment); \
	func(cursor_needs_physical); \
	func(hws_needs_physical); \
	func(overlay_needs_physical); \
	func(supports_tv); \
	func(has_ipc);

struct sseu_dev_info {
	u8 slice_mask;
	u8 subslice_mask;
	u8 eu_total;
	u8 eu_per_subslice;
	u8 min_eu_in_pool;
	/* For each slice, which subslice(s) has(have) 7 EUs (bitfield)? */
	u8 subslice_7eu[3];
	u8 has_slice_pg:1;
	u8 has_subslice_pg:1;
	u8 has_eu_pg:1;
};

struct intel_device_info {
	u16 device_id;
	u16 gen_mask;

	u8 gen;
	u8 gt; /* GT number, 0 if undefined */
	u8 num_rings;
	u8 ring_mask; /* Rings supported by the HW */

	enum intel_platform platform;
	u32 platform_mask;

	u32 display_mmio_offset;

	u8 num_pipes;
	u8 num_sprites[I915_MAX_PIPES];
	u8 num_scalers[I915_MAX_PIPES];

	unsigned int page_sizes; /* page sizes supported by the HW */

#define KLP_DEFINE_FLAG(name) u8 name:1
	KLP_DEV_INFO_FOR_EACH_FLAG(KLP_DEFINE_FLAG);
#undef KLP_DEFINE_FLAG
	u16 ddb_size; /* in blocks */

	/* Register offsets for the various display pipes and transcoders */
	int pipe_offsets[I915_MAX_TRANSCODERS];
	int trans_offsets[I915_MAX_TRANSCODERS];
	int palette_offsets[I915_MAX_PIPES];
	int cursor_offsets[I915_MAX_PIPES];

	/* Slice/subslice/EU info */
	struct sseu_dev_info sseu;

	u32 cs_timestamp_frequency_khz;

	struct color_luts {
		u16 degamma_lut_size;
		u16 gamma_lut_size;
	} color;
};


/* from drivers/gpu/drm/i915/i915_reg.h */
typedef struct {
	uint32_t reg;
} i915_reg_t;

#define KLP_GEN7_LRA_LIMITS_REG_NUM	13

#define   KLP_GMBUS_NUM_PINS	7 /* including 0 */

#define KLP_GEN7_GT_SCRATCH_REG_NUM			8


/* from drivers/gpu/drm/i915/intel_uncore.h */
struct drm_i915_private;

enum forcewake_domain_id {
	FW_DOMAIN_ID_RENDER = 0,
	FW_DOMAIN_ID_BLITTER,
	FW_DOMAIN_ID_MEDIA,

	FW_DOMAIN_ID_COUNT
};

enum forcewake_domains {
	FORCEWAKE_RENDER = BIT(FW_DOMAIN_ID_RENDER),
	FORCEWAKE_BLITTER = BIT(FW_DOMAIN_ID_BLITTER),
	FORCEWAKE_MEDIA	= BIT(FW_DOMAIN_ID_MEDIA),
	FORCEWAKE_ALL = (FORCEWAKE_RENDER |
			 FORCEWAKE_BLITTER |
			 FORCEWAKE_MEDIA)
};

struct intel_uncore_funcs {
	void (*force_wake_get)(struct drm_i915_private *dev_priv,
			       enum forcewake_domains domains);
	void (*force_wake_put)(struct drm_i915_private *dev_priv,
			       enum forcewake_domains domains);

	uint8_t  (*mmio_readb)(struct drm_i915_private *dev_priv,
			       i915_reg_t r, bool trace);
	uint16_t (*mmio_readw)(struct drm_i915_private *dev_priv,
			       i915_reg_t r, bool trace);
	uint32_t (*mmio_readl)(struct drm_i915_private *dev_priv,
			       i915_reg_t r, bool trace);
	uint64_t (*mmio_readq)(struct drm_i915_private *dev_priv,
			       i915_reg_t r, bool trace);

	void (*mmio_writeb)(struct drm_i915_private *dev_priv,
			    i915_reg_t r, uint8_t val, bool trace);
	void (*mmio_writew)(struct drm_i915_private *dev_priv,
			    i915_reg_t r, uint16_t val, bool trace);
	void (*mmio_writel)(struct drm_i915_private *dev_priv,
			    i915_reg_t r, uint32_t val, bool trace);
};

struct intel_uncore {
	spinlock_t lock; /** lock is also taken in irq contexts. */

	const struct intel_forcewake_range *fw_domains_table;
	unsigned int fw_domains_table_entries;

	struct notifier_block pmic_bus_access_nb;
	struct intel_uncore_funcs funcs;

	unsigned int fifo_count;

	enum forcewake_domains fw_domains;
	enum forcewake_domains fw_domains_active;
	enum forcewake_domains fw_domains_saved; /* user domains saved for S3 */

	u32 fw_set;
	u32 fw_clear;
	u32 fw_reset;

	struct intel_uncore_forcewake_domain {
		enum forcewake_domain_id id;
		enum forcewake_domains mask;
		unsigned int wake_count;
		bool active;
		struct hrtimer timer;
		i915_reg_t reg_set;
		i915_reg_t reg_ack;
	} fw_domain[FW_DOMAIN_ID_COUNT];

	struct {
		unsigned int count;

		int saved_mmio_check;
		int saved_mmio_debug;
	} user_forcewake;

	int unclaimed_mmio_check;
};


/* from drivers/gpu/drm/i915/intel_uc_fw.h */
enum intel_uc_fw_status {
	INTEL_UC_FIRMWARE_FAIL = -1,
	INTEL_UC_FIRMWARE_NONE = 0,
	INTEL_UC_FIRMWARE_PENDING,
	INTEL_UC_FIRMWARE_SUCCESS
};

enum intel_uc_fw_type {
	INTEL_UC_FW_TYPE_GUC,
	INTEL_UC_FW_TYPE_HUC
};

struct intel_uc_fw {
	const char *path;
	size_t size;
	struct drm_i915_gem_object *obj;
	enum intel_uc_fw_status fetch_status;
	enum intel_uc_fw_status load_status;

	/*
	 * The firmware build process will generate a version header file with major and
	 * minor version defined. The versions are built into CSS header of firmware.
	 * i915 kernel driver set the minimal firmware version required per platform.
	 */
	u16 major_ver_wanted;
	u16 minor_ver_wanted;
	u16 major_ver_found;
	u16 minor_ver_found;

	enum intel_uc_fw_type type;
	u32 header_size;
	u32 header_offset;
	u32 rsa_size;
	u32 rsa_offset;
	u32 ucode_size;
	u32 ucode_offset;
};

/* from drivers/gpu/drm/i915/intel_huc.h */
struct intel_huc {
	/* Generic uC firmware management */
	struct intel_uc_fw fw;

	/* HuC-specific additions */
};


/* from drivers/gpu/drm/i915/intel_guc_fwif.h */
#define KLP_GUC_NUM_DOORBELLS	256

enum guc_log_buffer_type {
	GUC_ISR_LOG_BUFFER,
	GUC_DPC_LOG_BUFFER,
	GUC_CRASH_DUMP_LOG_BUFFER,
	GUC_MAX_LOG_BUFFER
};

/* from drivers/gpu/drm/i915/intel_guc_log.h */
struct intel_guc_log {
	u32 flags;
	struct i915_vma *vma;
	/* The runtime stuff gets created only when GuC logging gets enabled */
	struct {
		void *buf_addr;
		struct workqueue_struct *flush_wq;
		struct work_struct flush_work;
		struct rchan *relay_chan;
	} runtime;
	/* logging related stats */
	u32 capture_miss_count;
	u32 flush_interrupt_count;
	u32 prev_overflow_count[GUC_MAX_LOG_BUFFER];
	u32 total_overflow_count[GUC_MAX_LOG_BUFFER];
	u32 flush_count[GUC_MAX_LOG_BUFFER];
};


/* from drivers/gpu/drm/i915/intel_guc_ct.h */
struct intel_guc_ct_buffer {
	struct guc_ct_buffer_desc *desc;
	u32 *cmds;
};

struct intel_guc_ct_channel {
	struct i915_vma *vma;
	struct intel_guc_ct_buffer ctbs[2];
	u32 owner;
	u32 next_fence;
};

struct intel_guc_ct {
	struct intel_guc_ct_channel host_channel;
	/* other channels are tbd */
};


/* from drivers/gpu/drm/i915/intel_guc.h */
struct guc_preempt_work {
	struct work_struct work;
	struct intel_engine_cs *engine;
};

struct intel_guc {
	struct intel_uc_fw fw;
	struct intel_guc_log log;
	struct intel_guc_ct ct;

	/* Log snapshot if GuC errors during load */
	struct drm_i915_gem_object *load_err_log;

	/* intel_guc_recv interrupt related state */
	bool interrupts_enabled;

	struct i915_vma *ads_vma;
	struct i915_vma *stage_desc_pool;
	void *stage_desc_pool_vaddr;
	struct ida stage_ids;
	struct i915_vma *shared_data;
	void *shared_data_vaddr;

	struct intel_guc_client *execbuf_client;
	struct intel_guc_client *preempt_client;

	struct guc_preempt_work preempt_work[KLP_I915_NUM_ENGINES];
	struct workqueue_struct *preempt_wq;

	DECLARE_BITMAP(doorbell_bitmap, KLP_GUC_NUM_DOORBELLS);
	/* Cyclic counter mod pagesize	*/
	u32 db_cacheline;

	/* GuC's FW specific registers used in MMIO send */
	struct {
		u32 base;
		unsigned int count;
		enum forcewake_domains fw_domains;
	} send_regs;

	/* To serialize the intel_guc_send actions */
	struct mutex send_mutex;

	/* GuC's FW specific send function */
	int (*send)(struct intel_guc *guc, const u32 *data, u32 len);

	/* GuC's FW specific notify function */
	void (*notify)(struct intel_guc *guc);
};


/* from drivers/gpu/drm/i915/intel_opregion.h */
struct intel_opregion {
	struct opregion_header *header;
	struct opregion_acpi *acpi;
	struct opregion_swsci *swsci;
	u32 swsci_gbda_sub_functions;
	u32 swsci_sbcb_sub_functions;
	struct opregion_asle *asle;
	void *rvda;
	void *vbt_firmware;
	const void *vbt;
	u32 vbt_size;
	u32 *lid_state;
	struct work_struct asle_work;
};


/* from drivers/gpu/drm/i915/intel_bios.h */
enum intel_backlight_type {
	INTEL_BACKLIGHT_PMIC,
	INTEL_BACKLIGHT_LPSS,
	INTEL_BACKLIGHT_DISPLAY_DDI,
	INTEL_BACKLIGHT_DSI_DCS,
	INTEL_BACKLIGHT_PANEL_DRIVER_INTERFACE,
};

struct edp_power_seq {
	u16 t1_t3;
	u16 t8;
	u16 t9;
	u16 t10;
	u16 t11_t12;
} __packed;

enum mipi_seq {
	MIPI_SEQ_END = 0,
	MIPI_SEQ_DEASSERT_RESET,	/* Spec says MipiAssertResetPin */
	MIPI_SEQ_INIT_OTP,
	MIPI_SEQ_DISPLAY_ON,
	MIPI_SEQ_DISPLAY_OFF,
	MIPI_SEQ_ASSERT_RESET,		/* Spec says MipiDeassertResetPin */
	MIPI_SEQ_BACKLIGHT_ON,		/* sequence block v2+ */
	MIPI_SEQ_BACKLIGHT_OFF,		/* sequence block v2+ */
	MIPI_SEQ_TEAR_ON,		/* sequence block v2+ */
	MIPI_SEQ_TEAR_OFF,		/* sequence block v3+ */
	MIPI_SEQ_POWER_ON,		/* sequence block v3+ */
	MIPI_SEQ_POWER_OFF,		/* sequence block v3+ */
	MIPI_SEQ_MAX
};


/* from drivers/gpu/drm/i915/i915_gem_fence_reg.h */
struct drm_i915_fence_reg {
	struct list_head link;
	struct drm_i915_private *i915;
	struct i915_vma *vma;
	int pin_count;
	int id;
	/**
	 * Whether the tiling parameters for the currently
	 * associated fence register have changed. Note that
	 * for the purposes of tracking tiling changes we also
	 * treat the unfenced register, the register slot that
	 * the object occupies whilst it executes a fenced
	 * command (such as BLT on gen2/3), as a "fence".
	 */
	bool dirty;
};


/* from drivers/gpu/drm/i915/i915_gem_request.h */
struct drm_i915_gem_request;

struct i915_gem_active;

typedef void (*i915_gem_retire_fn)(struct i915_gem_active *,
				   struct drm_i915_gem_request *);

struct i915_gem_active {
	struct drm_i915_gem_request __rcu *request;
	struct list_head link;
	i915_gem_retire_fn retire;
};


/* from drivers/gpu/drm/i915/i915_gem_timeline.h */
struct intel_timeline {
	u64 fence_context;
	u32 seqno;

	/**
	 * Count of outstanding requests, from the time they are constructed
	 * to the moment they are retired. Loosely coupled to hardware.
	 */
	u32 inflight_seqnos;

	spinlock_t lock;

	/**
	 * List of breadcrumbs associated with GPU requests currently
	 * outstanding.
	 */
	struct list_head requests;

	/* Contains an RCU guarded pointer to the last request. No reference is
	 * held to the request, users must carefully acquire a reference to
	 * the request using i915_gem_active_get_request_rcu(), or hold the
	 * struct_mutex.
	 */
	struct i915_gem_active last_request;

	/**
	 * We track the most recent seqno that we wait on in every context so
	 * that we only have to emit a new await and dependency on a more
	 * recent sync point. As the contexts may be executed out-of-order, we
	 * have to track each individually and can not rely on an absolute
	 * global_seqno. When we know that all tracked fences are completed
	 * (i.e. when the driver is idle), we know that the syncmap is
	 * redundant and we can discard it without loss of generality.
	 */
	struct i915_syncmap *sync;
	/**
	 * Separately to the inter-context seqno map above, we track the last
	 * barrier (e.g. semaphore wait) to the global engine timelines. Note
	 * that this tracks global_seqno rather than the context.seqno, and
	 * so it is subject to the limitations of hw wraparound and that we
	 * may need to revoke global_seqno (on pre-emption).
	 */
	u32 global_sync[KLP_I915_NUM_ENGINES];

	struct i915_gem_timeline *common;
};

struct i915_gem_timeline {
	struct list_head link;

	struct drm_i915_private *i915;
	const char *name;

	struct intel_timeline engine[KLP_I915_NUM_ENGINES];
};


/* from drivers/gpu/drm/i915/i915_gem_gtt.h */
#define KLP_I915_MAX_NUM_FENCES 32

typedef u32 gen6_pte_t;

enum i915_cache_level;

struct i915_page_dma {
	struct page *page;
	union {
		dma_addr_t daddr;

		/* For gen6/gen7 only. This is the offset in the GGTT
		 * where the page directory entries for PPGTT begin
		 */
		u32 ggtt_offset;
	};
};

struct i915_address_space {
	struct drm_mm mm;
	struct i915_gem_timeline timeline;
	struct drm_i915_private *i915;
	struct device *dma;
	/* Every address space belongs to a struct file - except for the global
	 * GTT that is owned by the driver (and so @file is set to NULL). In
	 * principle, no information should leak from one context to another
	 * (or between files/processes etc) unless explicitly shared by the
	 * owner. Tracking the owner is important in order to free up per-file
	 * objects along with the file, to aide resource tracking, and to
	 * assign blame.
	 */
	struct drm_i915_file_private *file;
	struct list_head global_link;
	u64 total;		/* size addr space maps (ex. 2GB for ggtt) */
	u64 reserved;		/* size addr space reserved */

	bool closed;

	struct i915_page_dma scratch_page;
	struct i915_page_table *scratch_pt;
	struct i915_page_directory *scratch_pd;
	struct i915_page_directory_pointer *scratch_pdp; /* GEN8+ & 48b PPGTT */

	/**
	 * List of objects currently involved in rendering.
	 *
	 * Includes buffers having the contents of their GPU caches
	 * flushed, not necessarily primitives. last_read_req
	 * represents when the rendering involved will be completed.
	 *
	 * A reference is held on the buffer while on this list.
	 */
	struct list_head active_list;

	/**
	 * LRU list of objects which are not in the ringbuffer and
	 * are ready to unbind, but are still in the GTT.
	 *
	 * last_read_req is NULL while an object is in this list.
	 *
	 * A reference is not held on the buffer while on this list,
	 * as merely being GTT-bound shouldn't prevent its being
	 * freed, and we'll pull it off the list in the free path.
	 */
	struct list_head inactive_list;

	/**
	 * List of vma that have been unbound.
	 *
	 * A reference is not held on the buffer while on this list.
	 */
	struct list_head unbound_list;

	struct pagevec free_pages;
	bool pt_kmap_wc;

	/* FIXME: Need a more generic return type */
	gen6_pte_t (*pte_encode)(dma_addr_t addr,
				 enum i915_cache_level level,
				 u32 flags); /* Create a valid PTE */
	/* flags for pte_encode */
#define PTE_READ_ONLY	(1<<0)
	int (*allocate_va_range)(struct i915_address_space *vm,
				 u64 start, u64 length);
	void (*clear_range)(struct i915_address_space *vm,
			    u64 start, u64 length);
	void (*insert_page)(struct i915_address_space *vm,
			    dma_addr_t addr,
			    u64 offset,
			    enum i915_cache_level cache_level,
			    u32 flags);
	void (*insert_entries)(struct i915_address_space *vm,
			       struct i915_vma *vma,
			       enum i915_cache_level cache_level,
			       u32 flags);
	void (*cleanup)(struct i915_address_space *vm);
	/** Unmap an object from an address space. This usually consists of
	 * setting the valid PTE entries to a reserved scratch page. */
	void (*unbind_vma)(struct i915_vma *vma);
	/* Map an object into an address space with the given cache flags. */
	int (*bind_vma)(struct i915_vma *vma,
			enum i915_cache_level cache_level,
			u32 flags);

	KLP_I915_SELFTEST_DECLARE(struct fault_attr fault_attr);
};

struct i915_ggtt {
	struct i915_address_space base;

	struct io_mapping iomap;	/* Mapping to our CPU mappable region */
	struct resource gmadr;          /* GMADR resource */
	resource_size_t mappable_end;	/* End offset that we can CPU map */

	/** "Graphics Stolen Memory" holds the global PTEs */
	void __iomem *gsm;
	void (*invalidate)(struct drm_i915_private *dev_priv);

	bool do_idle_maps;

	int mtrr;

	struct drm_mm_node error_capture;
};

#define KLP_INTEL_MAX_PPAT_ENTRIES 8

struct intel_ppat_entry {
	struct intel_ppat *ppat;
	struct kref ref;
	u8 value;
};

struct intel_ppat {
	struct intel_ppat_entry entries[KLP_INTEL_MAX_PPAT_ENTRIES];
	DECLARE_BITMAP(used, KLP_INTEL_MAX_PPAT_ENTRIES);
	DECLARE_BITMAP(dirty, KLP_INTEL_MAX_PPAT_ENTRIES);
	unsigned int max_entries;
	u8 clear_value;
	/*
	 * Return a score to show how two PPAT values match,
	 * a INTEL_PPAT_PERFECT_MATCH indicates a perfect match
	 */
	unsigned int (*match)(u8 src, u8 dst);
	void (*update_hw)(struct drm_i915_private *i915);

	struct drm_i915_private *i915;
};


/* from drivers/gpu/drm/i915/intel_dpll_mgr.h */
struct intel_shared_dpll;

enum intel_dpll_id {
	/**
	 * @DPLL_ID_PRIVATE: non-shared dpll in use
	 */
	DPLL_ID_PRIVATE = -1,

	/**
	 * @DPLL_ID_PCH_PLL_A: DPLL A in ILK, SNB and IVB
	 */
	DPLL_ID_PCH_PLL_A = 0,
	/**
	 * @DPLL_ID_PCH_PLL_B: DPLL B in ILK, SNB and IVB
	 */
	DPLL_ID_PCH_PLL_B = 1,


	/**
	 * @DPLL_ID_WRPLL1: HSW and BDW WRPLL1
	 */
	DPLL_ID_WRPLL1 = 0,
	/**
	 * @DPLL_ID_WRPLL2: HSW and BDW WRPLL2
	 */
	DPLL_ID_WRPLL2 = 1,
	/**
	 * @DPLL_ID_SPLL: HSW and BDW SPLL
	 */
	DPLL_ID_SPLL = 2,
	/**
	 * @DPLL_ID_LCPLL_810: HSW and BDW 0.81 GHz LCPLL
	 */
	DPLL_ID_LCPLL_810 = 3,
	/**
	 * @DPLL_ID_LCPLL_1350: HSW and BDW 1.35 GHz LCPLL
	 */
	DPLL_ID_LCPLL_1350 = 4,
	/**
	 * @DPLL_ID_LCPLL_2700: HSW and BDW 2.7 GHz LCPLL
	 */
	DPLL_ID_LCPLL_2700 = 5,


	/**
	 * @DPLL_ID_SKL_DPLL0: SKL and later DPLL0
	 */
	DPLL_ID_SKL_DPLL0 = 0,
	/**
	 * @DPLL_ID_SKL_DPLL1: SKL and later DPLL1
	 */
	DPLL_ID_SKL_DPLL1 = 1,
	/**
	 * @DPLL_ID_SKL_DPLL2: SKL and later DPLL2
	 */
	DPLL_ID_SKL_DPLL2 = 2,
	/**
	 * @DPLL_ID_SKL_DPLL3: SKL and later DPLL3
	 */
	DPLL_ID_SKL_DPLL3 = 3,
};

#define KLP_I915_NUM_PLLS 6

struct intel_dpll_hw_state {
	/* i9xx, pch plls */
	uint32_t dpll;
	uint32_t dpll_md;
	uint32_t fp0;
	uint32_t fp1;

	/* hsw, bdw */
	uint32_t wrpll;
	uint32_t spll;

	/* skl */
	/*
	 * DPLL_CTRL1 has 6 bits for each each this DPLL. We store those in
	 * lower part of ctrl1 and they get shifted into position when writing
	 * the register.  This allows us to easily compare the state to share
	 * the DPLL.
	 */
	uint32_t ctrl1;
	/* HDMI only, 0 when used for DP */
	uint32_t cfgcr1, cfgcr2;

	/* cnl */
	uint32_t cfgcr0;
	/* CNL also uses cfgcr1 */

	/* bxt */
	uint32_t ebb0, ebb4, pll0, pll1, pll2, pll3, pll6, pll8, pll9, pll10,
		 pcsdw12;
};

struct intel_shared_dpll_state {
	/**
	 * @crtc_mask: mask of CRTC using this DPLL, active or not
	 */
	unsigned crtc_mask;

	/**
	 * @hw_state: hardware configuration for the DPLL stored in
	 * struct &intel_dpll_hw_state.
	 */
	struct intel_dpll_hw_state hw_state;
};

struct intel_shared_dpll_funcs {
	/**
	 * @prepare:
	 *
	 * Optional hook to perform operations prior to enabling the PLL.
	 * Called from intel_prepare_shared_dpll() function unless the PLL
	 * is already enabled.
	 */
	void (*prepare)(struct drm_i915_private *dev_priv,
			struct intel_shared_dpll *pll);

	/**
	 * @enable:
	 *
	 * Hook for enabling the pll, called from intel_enable_shared_dpll()
	 * if the pll is not already enabled.
	 */
	void (*enable)(struct drm_i915_private *dev_priv,
		       struct intel_shared_dpll *pll);

	/**
	 * @disable:
	 *
	 * Hook for disabling the pll, called from intel_disable_shared_dpll()
	 * only when it is safe to disable the pll, i.e., there are no more
	 * tracked users for it.
	 */
	void (*disable)(struct drm_i915_private *dev_priv,
			struct intel_shared_dpll *pll);

	/**
	 * @get_hw_state:
	 *
	 * Hook for reading the values currently programmed to the DPLL
	 * registers. This is used for initial hw state readout and state
	 * verification after a mode set.
	 */
	bool (*get_hw_state)(struct drm_i915_private *dev_priv,
			     struct intel_shared_dpll *pll,
			     struct intel_dpll_hw_state *hw_state);
};

struct intel_shared_dpll {
	/**
	 * @state:
	 *
	 * Store the state for the pll, including the its hw state
	 * and CRTCs using it.
	 */
	struct intel_shared_dpll_state state;

	/**
	 * @active_mask: mask of active CRTCs (i.e. DPMS on) using this DPLL
	 */
	unsigned active_mask;

	/**
	 * @on: is the PLL actually active? Disabled during modeset
	 */
	bool on;

	/**
	 * @name: DPLL name; used for logging
	 */
	const char *name;

	/**
	 * @id: unique indentifier for this DPLL; should match the index in the
	 * dev_priv->shared_dplls array
	 */
	enum intel_dpll_id id;

	/**
	 * @funcs: platform specific hooks
	 */
	struct intel_shared_dpll_funcs funcs;

#define KLP_INTEL_DPLL_ALWAYS_ON	(1 << 0)
	/**
	 * @flags:
	 *
	 * INTEL_DPLL_ALWAYS_ON
	 *     Inform the state checker that the DPLL is kept enabled even if
	 *     not in use by any CRTC.
	 */
	uint32_t flags;
};


/* from drivers/gpu/drm/i915/i915_drv.h */
enum hpd_pin {
	HPD_NONE = 0,
	HPD_TV = HPD_NONE,     /* TV is known to be unreliable */
	HPD_CRT,
	HPD_SDVO_B,
	HPD_SDVO_C,
	HPD_PORT_A,
	HPD_PORT_B,
	HPD_PORT_C,
	HPD_PORT_D,
	HPD_PORT_E,
	HPD_NUM_PINS
};

struct i915_hotplug {
	struct work_struct hotplug_work;

	struct {
		unsigned long last_jiffies;
		int count;
		enum {
			HPD_ENABLED = 0,
			HPD_DISABLED = 1,
			HPD_MARK_DISABLED = 2
		} state;
	} stats[HPD_NUM_PINS];
	u32 event_bits;
	struct delayed_work reenable_work;

	struct intel_digital_port *irq_port[I915_MAX_PORTS];
	u32 long_port_mask;
	u32 short_port_mask;
	struct work_struct dig_port_work;

	struct work_struct poll_init_work;
	bool poll_enabled;

	unsigned int hpd_storm_threshold;

	/*
	 * if we get a HPD irq from DP and a HPD irq from non-DP
	 * the non-DP HPD could block the workqueue on a mode config
	 * mutex getting, that userspace may have taken. However
	 * userspace is waiting on the DP workqueue to run which is
	 * blocked behind the non-DP one.
	 */
	struct workqueue_struct *dp_wq;
};

struct sdvo_device_mapping {
	u8 initialized;
	u8 dvo_port;
	u8 slave_addr;
	u8 dvo_wiring;
	u8 i2c_pin;
	u8 ddc_pin;
};

struct intel_connector;
struct intel_encoder;
struct intel_atomic_state;
struct intel_crtc_state;
struct intel_initial_plane_config;
struct intel_crtc;
struct intel_limit;
struct dpll;
struct intel_cdclk_state;

struct drm_i915_display_funcs {
	void (*get_cdclk)(struct drm_i915_private *dev_priv,
			  struct intel_cdclk_state *cdclk_state);
	void (*set_cdclk)(struct drm_i915_private *dev_priv,
			  const struct intel_cdclk_state *cdclk_state);
	int (*get_fifo_size)(struct drm_i915_private *dev_priv,
			     enum i9xx_plane_id i9xx_plane);
	int (*compute_pipe_wm)(struct intel_crtc_state *cstate);
	int (*compute_intermediate_wm)(struct drm_device *dev,
				       struct intel_crtc *intel_crtc,
				       struct intel_crtc_state *newstate);
	void (*initial_watermarks)(struct intel_atomic_state *state,
				   struct intel_crtc_state *cstate);
	void (*atomic_update_watermarks)(struct intel_atomic_state *state,
					 struct intel_crtc_state *cstate);
	void (*optimize_watermarks)(struct intel_atomic_state *state,
				    struct intel_crtc_state *cstate);
	int (*compute_global_watermarks)(struct drm_atomic_state *state);
	void (*update_wm)(struct intel_crtc *crtc);
	int (*modeset_calc_cdclk)(struct drm_atomic_state *state);
	/* Returns the active state of the crtc, and if the crtc is active,
	 * fills out the pipe-config with the hw state. */
	bool (*get_pipe_config)(struct intel_crtc *,
				struct intel_crtc_state *);
	void (*get_initial_plane_config)(struct intel_crtc *,
					 struct intel_initial_plane_config *);
	int (*crtc_compute_clock)(struct intel_crtc *crtc,
				  struct intel_crtc_state *crtc_state);
	void (*crtc_enable)(struct intel_crtc_state *pipe_config,
			    struct drm_atomic_state *old_state);
	void (*crtc_disable)(struct intel_crtc_state *old_crtc_state,
			     struct drm_atomic_state *old_state);
	void (*update_crtcs)(struct drm_atomic_state *state);
	void (*audio_codec_enable)(struct intel_encoder *encoder,
				   const struct intel_crtc_state *crtc_state,
				   const struct drm_connector_state *conn_state);
	void (*audio_codec_disable)(struct intel_encoder *encoder,
				    const struct intel_crtc_state *old_crtc_state,
				    const struct drm_connector_state *old_conn_state);
	void (*fdi_link_train)(struct intel_crtc *crtc,
			       const struct intel_crtc_state *crtc_state);
	void (*init_clock_gating)(struct drm_i915_private *dev_priv);
	void (*hpd_irq_setup)(struct drm_i915_private *dev_priv);
	/* clock updates for mode set */
	/* cursor updates */
	/* render clock increase/decrease */
	/* display clock increase/decrease */
	/* pll clock increase/decrease */

	void (*load_csc_matrix)(struct drm_crtc_state *crtc_state);
	void (*load_luts)(struct drm_crtc_state *crtc_state);
};

struct intel_csr {
	struct work_struct work;
	const char *fw_path;
	uint32_t *dmc_payload;
	uint32_t dmc_fw_size;
	uint32_t version;
	uint32_t mmio_count;
	i915_reg_t mmioaddr[8];
	uint32_t mmiodata[8];
	uint32_t dc_state;
	uint32_t allowed_dc_mask;
};

struct intel_fbc {
	/* This is always the inner lock when overlapping with struct_mutex and
	 * it's the outer lock when overlapping with stolen_lock. */
	struct mutex lock;
	unsigned threshold;
	unsigned int possible_framebuffer_bits;
	unsigned int busy_bits;
	unsigned int visible_pipes_mask;
	struct intel_crtc *crtc;

	struct drm_mm_node compressed_fb;
	struct drm_mm_node *compressed_llb;

	bool false_color;

	bool enabled;
	bool active;

	bool underrun_detected;
	struct work_struct underrun_work;

	/*
	 * Due to the atomic rules we can't access some structures without the
	 * appropriate locking, so we cache information here in order to avoid
	 * these problems.
	 */
	struct intel_fbc_state_cache {
		struct i915_vma *vma;

		struct {
			unsigned int mode_flags;
			uint32_t hsw_bdw_pixel_rate;
		} crtc;

		struct {
			unsigned int rotation;
			int src_w;
			int src_h;
			bool visible;
			/*
			 * Display surface base address adjustement for
			 * pageflips. Note that on gen4+ this only adjusts up
			 * to a tile, offsets within a tile are handled in
			 * the hw itself (with the TILEOFF register).
			 */
			int adjusted_x;
			int adjusted_y;

			int y;
		} plane;

		struct {
			const struct drm_format_info *format;
			unsigned int stride;
		} fb;
	} state_cache;

	/*
	 * This structure contains everything that's relevant to program the
	 * hardware registers. When we want to figure out if we need to disable
	 * and re-enable FBC for a new configuration we just check if there's
	 * something different in the struct. The genx_fbc_activate functions
	 * are supposed to read from it in order to program the registers.
	 */
	struct intel_fbc_reg_params {
		struct i915_vma *vma;

		struct {
			enum pipe pipe;
			enum i9xx_plane_id i9xx_plane;
			unsigned int fence_y_offset;
		} crtc;

		struct {
			const struct drm_format_info *format;
			unsigned int stride;
		} fb;

		int cfb_size;
		unsigned int gen9_wa_cfb_stride;
	} params;

	struct intel_fbc_work {
		bool scheduled;
		u32 scheduled_vblank;
		struct work_struct work;
	} work;

	const char *no_fbc_reason;
};

enum drrs_refresh_rate_type {
	DRRS_HIGH_RR,
	DRRS_LOW_RR,
	DRRS_MAX_RR, /* RR count */
};

enum drrs_support_type {
	DRRS_NOT_SUPPORTED = 0,
	STATIC_DRRS_SUPPORT = 1,
	SEAMLESS_DRRS_SUPPORT = 2
};

struct i915_drrs {
	struct mutex mutex;
	struct delayed_work work;
	struct intel_dp *dp;
	unsigned busy_frontbuffer_bits;
	enum drrs_refresh_rate_type refresh_rate_type;
	enum drrs_support_type type;
};

struct i915_psr {
	struct mutex lock;
	bool sink_support;
	bool source_ok;
	struct intel_dp *enabled;
	bool active;
	struct delayed_work work;
	unsigned busy_frontbuffer_bits;
	bool psr2_support;
	bool aux_frame_sync;
	bool link_standby;
	bool y_cord_support;
	bool colorimetry_support;
	bool alpm;

	void (*enable_source)(struct intel_dp *,
			      const struct intel_crtc_state *);
	void (*disable_source)(struct intel_dp *,
			       const struct intel_crtc_state *);
	void (*enable_sink)(struct intel_dp *);
	void (*activate)(struct intel_dp *);
	void (*setup_vsc)(struct intel_dp *, const struct intel_crtc_state *);
};

enum intel_pch {
	PCH_NONE = 0,	/* No PCH present */
	PCH_IBX,	/* Ibexpeak PCH */
	PCH_CPT,	/* Cougarpoint/Pantherpoint PCH */
	PCH_LPT,	/* Lynxpoint/Wildcatpoint PCH */
	PCH_SPT,        /* Sunrisepoint PCH */
	PCH_KBP,        /* Kaby Lake PCH */
	PCH_CNP,        /* Cannon Lake PCH */
	PCH_NOP,
};

struct intel_gmbus {
	struct i2c_adapter adapter;
#define KLP_GMBUS_FORCE_BIT_RETRY (1U << 31)
	u32 force_bit;
	u32 reg0;
	i915_reg_t gpio_reg;
	struct i2c_algo_bit_data bit_algo;
	struct drm_i915_private *dev_priv;
};

struct i915_suspend_saved_registers {
	u32 saveDSPARB;
	u32 saveFBC_CONTROL;
	u32 saveCACHE_MODE_0;
	u32 saveMI_ARB_STATE;
	u32 saveSWF0[16];
	u32 saveSWF1[16];
	u32 saveSWF3[3];
	uint64_t saveFENCE[KLP_I915_MAX_NUM_FENCES];
	u32 savePCH_PORT_HOTPLUG;
	u16 saveGCDGMBUS;
};

struct vlv_s0ix_state {
	/* GAM */
	u32 wr_watermark;
	u32 gfx_prio_ctrl;
	u32 arb_mode;
	u32 gfx_pend_tlb0;
	u32 gfx_pend_tlb1;
	u32 lra_limits[KLP_GEN7_LRA_LIMITS_REG_NUM];
	u32 media_max_req_count;
	u32 gfx_max_req_count;
	u32 render_hwsp;
	u32 ecochk;
	u32 bsd_hwsp;
	u32 blt_hwsp;
	u32 tlb_rd_addr;

	/* MBC */
	u32 g3dctl;
	u32 gsckgctl;
	u32 mbctl;

	/* GCP */
	u32 ucgctl1;
	u32 ucgctl3;
	u32 rcgctl1;
	u32 rcgctl2;
	u32 rstctl;
	u32 misccpctl;

	/* GPM */
	u32 gfxpause;
	u32 rpdeuhwtc;
	u32 rpdeuc;
	u32 ecobus;
	u32 pwrdwnupctl;
	u32 rp_down_timeout;
	u32 rp_deucsw;
	u32 rcubmabdtmr;
	u32 rcedata;
	u32 spare2gh;

	/* Display 1 CZ domain */
	u32 gt_imr;
	u32 gt_ier;
	u32 pm_imr;
	u32 pm_ier;
	u32 gt_scratch[KLP_GEN7_GT_SCRATCH_REG_NUM];

	/* GT SA CZ domain */
	u32 tilectl;
	u32 gt_fifoctl;
	u32 gtlc_wake_ctrl;
	u32 gtlc_survive;
	u32 pmwgicz;

	/* Display 2 CZ domain */
	u32 gu_ctl0;
	u32 gu_ctl1;
	u32 pcbr;
	u32 clock_gate_dis2;
};

struct intel_rps_ei {
	ktime_t ktime;
	u32 render_c0;
	u32 media_c0;
};

struct intel_rps {
	/*
	 * work, interrupts_enabled and pm_iir are protected by
	 * dev_priv->irq_lock
	 */
	struct work_struct work;
	bool interrupts_enabled;
	u32 pm_iir;

	/* PM interrupt bits that should never be masked */
	u32 pm_intrmsk_mbz;

	/* Frequencies are stored in potentially platform dependent multiples.
	 * In other words, *_freq needs to be multiplied by X to be interesting.
	 * Soft limits are those which are used for the dynamic reclocking done
	 * by the driver (raise frequencies under heavy loads, and lower for
	 * lighter loads). Hard limits are those imposed by the hardware.
	 *
	 * A distinction is made for overclocking, which is never enabled by
	 * default, and is considered to be above the hard limit if it's
	 * possible at all.
	 */
	u8 cur_freq;		/* Current frequency (cached, may not == HW) */
	u8 min_freq_softlimit;	/* Minimum frequency permitted by the driver */
	u8 max_freq_softlimit;	/* Max frequency permitted by the driver */
	u8 max_freq;		/* Maximum frequency, RP0 if not overclocking */
	u8 min_freq;		/* AKA RPn. Minimum frequency */
	u8 boost_freq;		/* Frequency to request when wait boosting */
	u8 idle_freq;		/* Frequency to request when we are idle */
	u8 efficient_freq;	/* AKA RPe. Pre-determined balanced frequency */
	u8 rp1_freq;		/* "less than" RP0 power/freqency */
	u8 rp0_freq;		/* Non-overclocked max frequency. */
	u16 gpll_ref_freq;	/* vlv/chv GPLL reference frequency */

	u8 up_threshold; /* Current %busy required to uplock */
	u8 down_threshold; /* Current %busy required to downclock */

	int last_adj;
	enum { LOW_POWER, BETWEEN, HIGH_POWER } power;

	bool enabled;
	atomic_t num_waiters;
	atomic_t boosts;

	/* manual wa residency calculations */
	struct intel_rps_ei ei;
};

struct intel_rc6 {
	bool enabled;
};

struct intel_llc_pstate {
	bool enabled;
};

struct intel_gen6_power_mgmt {
	struct intel_rps rps;
	struct intel_rc6 rc6;
	struct intel_llc_pstate llc_pstate;
};

struct intel_ilk_power_mgmt {
	u8 cur_delay;
	u8 min_delay;
	u8 max_delay;
	u8 fmax;
	u8 fstart;

	u64 last_count1;
	unsigned long last_time1;
	unsigned long chipset_power;
	u64 last_count2;
	u64 last_time2;
	unsigned long gfx_power;
	u8 corr;

	int c_m;
	int r_t;
};

struct i915_power_domains {
	/*
	 * Power wells needed for initialization at driver init and suspend
	 * time are on. They are kept on until after the first modeset.
	 */
	bool init_power_on;
	bool initializing;
	int power_well_count;

	struct mutex lock;
	int domain_use_count[POWER_DOMAIN_NUM];
	struct i915_power_well *power_wells;
};

#define KLP_MAX_L3_SLICES 2
struct intel_l3_parity {
	u32 *remap_info[KLP_MAX_L3_SLICES];
	struct work_struct error_work;
	int which_slice;
};

struct i915_gem_mm {
	/** Memory allocator for GTT stolen memory */
	struct drm_mm stolen;
	/** Protects the usage of the GTT stolen memory allocator. This is
	 * always the inner lock when overlapping with struct_mutex. */
	struct mutex stolen_lock;

	/* Protects bound_list/unbound_list and #drm_i915_gem_object.mm.link */
	spinlock_t obj_lock;

	/** List of all objects in gtt_space. Used to restore gtt
	 * mappings on resume */
	struct list_head bound_list;
	/**
	 * List of objects which are not bound to the GTT (thus
	 * are idle and not used by the GPU). These objects may or may
	 * not actually have any pages attached.
	 */
	struct list_head unbound_list;

	/** List of all objects in gtt_space, currently mmaped by userspace.
	 * All objects within this list must also be on bound_list.
	 */
	struct list_head userfault_list;

	/**
	 * List of objects which are pending destruction.
	 */
	struct llist_head free_list;
	struct work_struct free_work;
	spinlock_t free_lock;

	/**
	 * Small stash of WC pages
	 */
	struct pagevec wc_stash;

	/** PPGTT used for aliasing the PPGTT with the GTT */
	struct i915_hw_ppgtt *aliasing_ppgtt;

	struct notifier_block oom_notifier;
	struct notifier_block vmap_notifier;
	struct shrinker shrinker;

	/** LRU list of objects with fence regs on them. */
	struct list_head fence_list;

	/**
	 * Workqueue to fault in userptr pages, flushed by the execbuf
	 * when required but otherwise left to userspace to try again
	 * on EAGAIN.
	 */
	struct workqueue_struct *userptr_wq;

	u64 unordered_timeline;

	/* the indicator for dispatch video commands on two BSD rings */
	atomic_t bsd_engine_dispatch_index;

	/** Bit 6 swizzling required for X tiling */
	uint32_t bit_6_swizzle_x;
	/** Bit 6 swizzling required for Y tiling */
	uint32_t bit_6_swizzle_y;

	/* accounting, useful for userland debugging */
	spinlock_t object_stat_lock;
	u64 object_memory;
	u32 object_count;
};

struct i915_gpu_error {
	/* For hangcheck timer */
#define KLP_DRM_I915_HANGCHECK_PERIOD 1500 /* in ms */
#define KLP_DRM_I915_HANGCHECK_JIFFIES msecs_to_jiffies(KLP_DRM_I915_HANGCHECK_PERIOD)

	struct delayed_work hangcheck_work;

	/* For reset and error_state handling. */
	spinlock_t lock;
	/* Protected by the above dev->gpu_error.lock. */
	struct i915_gpu_state *first_error;

	atomic_t pending_fb_pin;

	unsigned long missed_irq_rings;

	/**
	 * State variable controlling the reset flow and count
	 *
	 * This is a counter which gets incremented when reset is triggered,
	 *
	 * Before the reset commences, the I915_RESET_BACKOFF bit is set
	 * meaning that any waiters holding onto the struct_mutex should
	 * relinquish the lock immediately in order for the reset to start.
	 *
	 * If reset is not completed succesfully, the I915_WEDGE bit is
	 * set meaning that hardware is terminally sour and there is no
	 * recovery. All waiters on the reset_queue will be woken when
	 * that happens.
	 *
	 * This counter is used by the wait_seqno code to notice that reset
	 * event happened and it needs to restart the entire ioctl (since most
	 * likely the seqno it waited for won't ever signal anytime soon).
	 *
	 * This is important for lock-free wait paths, where no contended lock
	 * naturally enforces the correct ordering between the bail-out of the
	 * waiter and the gpu reset work code.
	 */
	unsigned long reset_count;

	/**
	 * flags: Control various stages of the GPU reset
	 *
	 * #I915_RESET_BACKOFF - When we start a reset, we want to stop any
	 * other users acquiring the struct_mutex. To do this we set the
	 * #I915_RESET_BACKOFF bit in the error flags when we detect a reset
	 * and then check for that bit before acquiring the struct_mutex (in
	 * i915_mutex_lock_interruptible()?). I915_RESET_BACKOFF serves a
	 * secondary role in preventing two concurrent global reset attempts.
	 *
	 * #I915_RESET_HANDOFF - To perform the actual GPU reset, we need the
	 * struct_mutex. We try to acquire the struct_mutex in the reset worker,
	 * but it may be held by some long running waiter (that we cannot
	 * interrupt without causing trouble). Once we are ready to do the GPU
	 * reset, we set the I915_RESET_HANDOFF bit and wakeup any waiters. If
	 * they already hold the struct_mutex and want to participate they can
	 * inspect the bit and do the reset directly, otherwise the worker
	 * waits for the struct_mutex.
	 *
	 * #I915_RESET_ENGINE[num_engines] - Since the driver doesn't need to
	 * acquire the struct_mutex to reset an engine, we need an explicit
	 * flag to prevent two concurrent reset attempts in the same engine.
	 * As the number of engines continues to grow, allocate the flags from
	 * the most significant bits.
	 *
	 * #I915_WEDGED - If reset fails and we can no longer use the GPU,
	 * we set the #I915_WEDGED bit. Prior to command submission, e.g.
	 * i915_gem_request_alloc(), this bit is checked and the sequence
	 * aborted (with -EIO reported to userspace) if set.
	 */
	unsigned long flags;
#define KLP_I915_RESET_BACKOFF	0
#define KLP_I915_RESET_HANDOFF	1
#define KLP_I915_RESET_MODESET	2
#define KLP_I915_WEDGED		(BITS_PER_LONG - 1)
#define KLP_I915_RESET_ENGINE	(KLP_I915_WEDGED - KLP_I915_NUM_ENGINES)

	/** Number of times an engine has been reset */
	u32 reset_engine_count[KLP_I915_NUM_ENGINES];

	/**
	 * Waitqueue to signal when a hang is detected. Used to for waiters
	 * to release the struct_mutex for the reset to procede.
	 */
	wait_queue_head_t wait_queue;

	/**
	 * Waitqueue to signal when the reset has completed. Used by clients
	 * that wait for dev_priv->mm.wedged to settle.
	 */
	wait_queue_head_t reset_queue;

	/* For missed irq/seqno simulation. */
	unsigned long test_irq_rings;
};

struct ddi_vbt_port_info {
	int max_tmds_clock;

	/*
	 * This is an index in the HDMI/DVI DDI buffer translation table.
	 * The special value HDMI_LEVEL_SHIFT_UNKNOWN means the VBT didn't
	 * populate this field.
	 */
#define KLP_HDMI_LEVEL_SHIFT_UNKNOWN	0xff
	uint8_t hdmi_level_shift;

	uint8_t supports_dvi:1;
	uint8_t supports_hdmi:1;
	uint8_t supports_dp:1;
	uint8_t supports_edp:1;

	uint8_t alternate_aux_channel;
	uint8_t alternate_ddc_pin;

	uint8_t dp_boost_level;
	uint8_t hdmi_boost_level;
	int dp_max_link_rate;		/* 0 for not limited by VBT */
};

enum psr_lines_to_wait {
	PSR_0_LINES_TO_WAIT = 0,
	PSR_1_LINE_TO_WAIT,
	PSR_4_LINES_TO_WAIT,
	PSR_8_LINES_TO_WAIT
};

struct intel_vbt_data {
	struct drm_display_mode *lfp_lvds_vbt_mode; /* if any */
	struct drm_display_mode *sdvo_lvds_vbt_mode; /* if any */

	/* Feature bits */
	unsigned int int_tv_support:1;
	unsigned int lvds_dither:1;
	unsigned int lvds_vbt:1;
	unsigned int int_crt_support:1;
	unsigned int lvds_use_ssc:1;
	unsigned int display_clock_mode:1;
	unsigned int fdi_rx_polarity_inverted:1;
	unsigned int panel_type:4;
	int lvds_ssc_freq;
	unsigned int bios_lvds_val; /* initial [PCH_]LVDS reg val in VBIOS */

	enum drrs_support_type drrs_type;

	struct {
		int rate;
		int lanes;
		int preemphasis;
		int vswing;
		bool low_vswing;
		bool initialized;
		bool support;
		int bpp;
		struct edp_power_seq pps;
	} edp;

	struct {
		bool full_link;
		bool require_aux_wakeup;
		int idle_frames;
		enum psr_lines_to_wait lines_to_wait;
		int tp1_wakeup_time;
		int tp2_tp3_wakeup_time;
	} psr;

	struct {
		u16 pwm_freq_hz;
		bool present;
		bool active_low_pwm;
		u8 min_brightness;	/* min_brightness/255 of max */
		u8 controller;		/* brightness controller number */
		enum intel_backlight_type type;
	} backlight;

	/* MIPI DSI */
	struct {
		u16 panel_id;
		struct mipi_config *config;
		struct mipi_pps_data *pps;
		u16 bl_ports;
		u16 cabc_ports;
		u8 seq_version;
		u32 size;
		u8 *data;
		const u8 *sequence[MIPI_SEQ_MAX];
		u8 *deassert_seq; /* Used by fixup_mipi_sequences() */
	} dsi;

	int crt_ddc_pin;

	int child_dev_num;
	struct child_device_config *child_dev;

	struct ddi_vbt_port_info ddi_port_info[I915_MAX_PORTS];
	struct sdvo_device_mapping sdvo_mappings[2];
};

enum intel_ddb_partitioning {
	INTEL_DDB_PART_1_2,
	INTEL_DDB_PART_5_6, /* IVB+ */
};

struct ilk_wm_values {
	uint32_t wm_pipe[3];
	uint32_t wm_lp[3];
	uint32_t wm_lp_spr[3];
	uint32_t wm_linetime[3];
	bool enable_fbc_wm;
	enum intel_ddb_partitioning partitioning;
};

struct g4x_pipe_wm {
	uint16_t plane[I915_MAX_PLANES];
	uint16_t fbc;
};

struct g4x_sr_wm {
	uint16_t plane;
	uint16_t cursor;
	uint16_t fbc;
};

struct vlv_wm_ddl_values {
	uint8_t plane[I915_MAX_PLANES];
};

struct vlv_wm_values {
	struct g4x_pipe_wm pipe[3];
	struct g4x_sr_wm sr;
	struct vlv_wm_ddl_values ddl[3];
	uint8_t level;
	bool cxsr;
};

struct g4x_wm_values {
	struct g4x_pipe_wm pipe[2];
	struct g4x_sr_wm sr;
	struct g4x_sr_wm hpll;
	bool cxsr;
	bool hpll_en;
	bool fbc_en;
};

struct skl_ddb_entry {
	uint16_t start, end;	/* in number of blocks, 'end' is exclusive */
};

struct skl_ddb_allocation {
	struct skl_ddb_entry plane[I915_MAX_PIPES][I915_MAX_PLANES]; /* packed/uv */
	struct skl_ddb_entry y_plane[I915_MAX_PIPES][I915_MAX_PLANES];
};

struct skl_wm_values {
	unsigned dirty_pipes;
	struct skl_ddb_allocation ddb;
};

struct i915_runtime_pm {
	atomic_t wakeref_count;
	bool suspended;
	bool irqs_enabled;
};

enum intel_pipe_crc_source {
	INTEL_PIPE_CRC_SOURCE_NONE,
	INTEL_PIPE_CRC_SOURCE_PLANE1,
	INTEL_PIPE_CRC_SOURCE_PLANE2,
	INTEL_PIPE_CRC_SOURCE_PF,
	INTEL_PIPE_CRC_SOURCE_PIPE,
	/* TV/DP on pre-gen5/vlv can't use the pipe source. */
	INTEL_PIPE_CRC_SOURCE_TV,
	INTEL_PIPE_CRC_SOURCE_DP_B,
	INTEL_PIPE_CRC_SOURCE_DP_C,
	INTEL_PIPE_CRC_SOURCE_DP_D,
	INTEL_PIPE_CRC_SOURCE_AUTO,
	INTEL_PIPE_CRC_SOURCE_MAX,
};

struct intel_pipe_crc {
	spinlock_t lock;
	bool opened;		/* exclusive access to the result file */
	struct intel_pipe_crc_entry *entries;
	enum intel_pipe_crc_source source;
	int head, tail;
	wait_queue_head_t wq;
	int skipped;
};

struct i915_frontbuffer_tracking {
	spinlock_t lock;

	/*
	 * Tracking bits for delayed frontbuffer flushing du to gpu activity or
	 * scheduled flips.
	 */
	unsigned busy_bits;
	unsigned flip_bits;
};

struct i915_wa_reg {
	i915_reg_t addr;
	u32 value;
	/* bitmask representing WA bits */
	u32 mask;
};

#define KLP_I915_MAX_WA_REGS 16

struct i915_workarounds {
	struct i915_wa_reg reg[KLP_I915_MAX_WA_REGS];
	u32 count;
	u32 hw_whitelist_count[KLP_I915_NUM_ENGINES];
};

struct i915_virtual_gpu {
	bool active;
	u32 caps;
};

struct i915_oa_config {
	char uuid[UUID_STRING_LEN + 1];
	int id;

	const struct i915_oa_reg *mux_regs;
	u32 mux_regs_len;
	const struct i915_oa_reg *b_counter_regs;
	u32 b_counter_regs_len;
	const struct i915_oa_reg *flex_regs;
	u32 flex_regs_len;

	struct attribute_group sysfs_metric;
	struct attribute *attrs[2];
	struct device_attribute sysfs_metric_id;

	atomic_t ref_count;
};

struct i915_perf_stream;

struct i915_oa_ops {
	/**
	 * @is_valid_b_counter_reg: Validates register's address for
	 * programming boolean counters for a particular platform.
	 */
	bool (*is_valid_b_counter_reg)(struct drm_i915_private *dev_priv,
				       u32 addr);

	/**
	 * @is_valid_mux_reg: Validates register's address for programming mux
	 * for a particular platform.
	 */
	bool (*is_valid_mux_reg)(struct drm_i915_private *dev_priv, u32 addr);

	/**
	 * @is_valid_flex_reg: Validates register's address for programming
	 * flex EU filtering for a particular platform.
	 */
	bool (*is_valid_flex_reg)(struct drm_i915_private *dev_priv, u32 addr);

	/**
	 * @init_oa_buffer: Resets the head and tail pointers of the
	 * circular buffer for periodic OA reports.
	 *
	 * Called when first opening a stream for OA metrics, but also may be
	 * called in response to an OA buffer overflow or other error
	 * condition.
	 *
	 * Note it may be necessary to clear the full OA buffer here as part of
	 * maintaining the invariable that new reports must be written to
	 * zeroed memory for us to be able to reliable detect if an expected
	 * report has not yet landed in memory.  (At least on Haswell the OA
	 * buffer tail pointer is not synchronized with reports being visible
	 * to the CPU)
	 */
	void (*init_oa_buffer)(struct drm_i915_private *dev_priv);

	/**
	 * @enable_metric_set: Selects and applies any MUX configuration to set
	 * up the Boolean and Custom (B/C) counters that are part of the
	 * counter reports being sampled. May apply system constraints such as
	 * disabling EU clock gating as required.
	 */
	int (*enable_metric_set)(struct drm_i915_private *dev_priv,
				 const struct i915_oa_config *oa_config);

	/**
	 * @disable_metric_set: Remove system constraints associated with using
	 * the OA unit.
	 */
	void (*disable_metric_set)(struct drm_i915_private *dev_priv);

	/**
	 * @oa_enable: Enable periodic sampling
	 */
	void (*oa_enable)(struct drm_i915_private *dev_priv);

	/**
	 * @oa_disable: Disable periodic sampling
	 */
	void (*oa_disable)(struct drm_i915_private *dev_priv);

	/**
	 * @read: Copy data from the circular OA buffer into a given userspace
	 * buffer.
	 */
	int (*read)(struct i915_perf_stream *stream,
		    char __user *buf,
		    size_t count,
		    size_t *offset);

	/**
	 * @oa_hw_tail_read: read the OA tail pointer register
	 *
	 * In particular this enables us to share all the fiddly code for
	 * handling the OA unit tail pointer race that affects multiple
	 * generations.
	 */
	u32 (*oa_hw_tail_read)(struct drm_i915_private *dev_priv);
};

struct intel_cdclk_state {
	unsigned int cdclk, vco, ref;
	u8 voltage_level;
};

struct drm_i915_private {
	struct drm_device drm;

	struct kmem_cache *objects;
	struct kmem_cache *vmas;
	struct kmem_cache *luts;
	struct kmem_cache *requests;
	struct kmem_cache *dependencies;
	struct kmem_cache *priorities;

	const struct intel_device_info info;

	/**
	 * Data Stolen Memory - aka "i915 stolen memory" gives us the start and
	 * end of stolen which we can optionally use to create GEM objects
	 * backed by stolen memory. Note that stolen_usable_size tells us
	 * exactly how much of this we are actually allowed to use, given that
	 * some portion of it is in fact reserved for use by hardware functions.
	 */
	struct resource dsm;
	/**
	 * Reseved portion of Data Stolen Memory
	 */
	struct resource dsm_reserved;

	/*
	 * Stolen memory is segmented in hardware with different portions
	 * offlimits to certain functions.
	 *
	 * The drm_mm is initialised to the total accessible range, as found
	 * from the PCI config. On Broadwell+, this is further restricted to
	 * avoid the first page! The upper end of stolen memory is reserved for
	 * hardware functions and similarly removed from the accessible range.
	 */
	resource_size_t stolen_usable_size;	/* Total size minus reserved ranges */

	void __iomem *regs;

	struct intel_uncore uncore;

	struct i915_virtual_gpu vgpu;

	struct intel_gvt *gvt;

	struct intel_huc huc;
	struct intel_guc guc;

	struct intel_csr csr;

	struct intel_gmbus gmbus[KLP_GMBUS_NUM_PINS];

	/** gmbus_mutex protects against concurrent usage of the single hw gmbus
	 * controller on different i2c buses. */
	struct mutex gmbus_mutex;

	/**
	 * Base address of the gmbus and gpio block.
	 */
	uint32_t gpio_mmio_base;

	/* MMIO base address for MIPI regs */
	uint32_t mipi_mmio_base;

	uint32_t psr_mmio_base;

	uint32_t pps_mmio_base;

	wait_queue_head_t gmbus_wait_queue;

	struct pci_dev *bridge_dev;
	struct intel_engine_cs *engine[KLP_I915_NUM_ENGINES];
	/* Context used internally to idle the GPU and setup initial state */
	struct i915_gem_context *kernel_context;
	/* Context only to be used for injecting preemption commands */
	struct i915_gem_context *preempt_context;

	struct drm_dma_handle *status_page_dmah;
	struct resource mch_res;

	/* protects the irq masks */
	spinlock_t irq_lock;

	bool display_irqs_enabled;

	/* To control wakeup latency, e.g. for irq-driven dp aux transfers. */
	struct pm_qos_request pm_qos;

	/* Sideband mailbox protection */
	struct mutex sb_lock;

	/** Cached value of IMR to avoid reads in updating the bitfield */
	union {
		u32 irq_mask;
		u32 de_irq_mask[I915_MAX_PIPES];
	};
	u32 gt_irq_mask;
	u32 pm_imr;
	u32 pm_ier;
	u32 pm_rps_events;
	u32 pm_guc_events;
	u32 pipestat_irq_mask[I915_MAX_PIPES];

	struct i915_hotplug hotplug;
	struct intel_fbc fbc;
	struct i915_drrs drrs;
	struct intel_opregion opregion;
	struct intel_vbt_data vbt;

	bool preserve_bios_swizzle;

	/* overlay */
	struct intel_overlay *overlay;

	/* backlight registers and fields in struct intel_panel */
	struct mutex backlight_lock;

	/* LVDS info */
	bool no_aux_handshake;

	/* protects panel power sequencer state */
	struct mutex pps_mutex;

	struct drm_i915_fence_reg fence_regs[KLP_I915_MAX_NUM_FENCES]; /* assume 965 */
	int num_fence_regs; /* 8 on pre-965, 16 otherwise */

	unsigned int fsb_freq, mem_freq, is_ddr3;
	unsigned int skl_preferred_vco_freq;
	unsigned int max_cdclk_freq;

	unsigned int max_dotclk_freq;
	unsigned int rawclk_freq;
	unsigned int hpll_freq;
	unsigned int fdi_pll_freq;
	unsigned int czclk_freq;

	struct {
		/*
		 * The current logical cdclk state.
		 * See intel_atomic_state.cdclk.logical
		 *
		 * For reading holding any crtc lock is sufficient,
		 * for writing must hold all of them.
		 */
		struct intel_cdclk_state logical;
		/*
		 * The current actual cdclk state.
		 * See intel_atomic_state.cdclk.actual
		 */
		struct intel_cdclk_state actual;
		/* The current hardware cdclk state */
		struct intel_cdclk_state hw;
	} cdclk;

	/**
	 * wq - Driver workqueue for GEM.
	 *
	 * NOTE: Work items scheduled here are not allowed to grab any modeset
	 * locks, for otherwise the flushing done in the pageflip code will
	 * result in deadlocks.
	 */
	struct workqueue_struct *wq;

	/* ordered wq for modesets */
	struct workqueue_struct *modeset_wq;

	/* Display functions */
	struct drm_i915_display_funcs display;

	/* PCH chipset type */
	enum intel_pch pch_type;
	unsigned short pch_id;

	unsigned long quirks;

	struct drm_atomic_state *modeset_restore_state;
	struct drm_modeset_acquire_ctx reset_ctx;

	struct list_head vm_list; /* Global list of all address spaces */
	struct i915_ggtt ggtt; /* VM representing the global address space */

	struct i915_gem_mm mm;
	DECLARE_HASHTABLE(mm_structs, 7);
	struct mutex mm_lock;

	struct intel_ppat ppat;

	/* Kernel Modesetting */

	struct intel_crtc *plane_to_crtc_mapping[I915_MAX_PIPES];
	struct intel_crtc *pipe_to_crtc_mapping[I915_MAX_PIPES];

#ifdef CONFIG_DEBUG_FS
	struct intel_pipe_crc pipe_crc[I915_MAX_PIPES];
#endif

	/* dpll and cdclk state is protected by connection_mutex */
	int num_shared_dpll;
	struct intel_shared_dpll shared_dplls[KLP_I915_NUM_PLLS];
	const struct intel_dpll_mgr *dpll_mgr;

	/*
	 * dpll_lock serializes intel_{prepare,enable,disable}_shared_dpll.
	 * Must be global rather than per dpll, because on some platforms
	 * plls share registers.
	 */
	struct mutex dpll_lock;

	unsigned int active_crtcs;
	/* minimum acceptable cdclk for each pipe */
	int min_cdclk[I915_MAX_PIPES];
	/* minimum acceptable voltage level for each pipe */
	u8 min_voltage_level[I915_MAX_PIPES];

	int dpio_phy_iosf_port[KLP_I915_NUM_PHYS_VLV];

	struct i915_workarounds workarounds;

	struct i915_frontbuffer_tracking fb_tracking;

	struct intel_atomic_helper {
		struct llist_head free_list;
		struct work_struct free_work;
	} atomic_helper;

	u16 orig_clock;

	bool mchbar_need_disable;

	struct intel_l3_parity l3_parity;

	/* Cannot be determined by PCIID. You must always read a register. */
	u32 edram_cap;

	/*
	 * Protects RPS/RC6 register access and PCU communication.
	 * Must be taken after struct_mutex if nested. Note that
	 * this lock may be held for long periods of time when
	 * talking to hw - so only take it when talking to hw!
	 */
	struct mutex pcu_lock;

	/* gen6+ GT PM state */
	struct intel_gen6_power_mgmt gt_pm;

	/* ilk-only ips/rps state. Everything in here is protected by the global
	 * mchdev_lock in intel_pm.c */
	struct intel_ilk_power_mgmt ips;

	struct i915_power_domains power_domains;

	struct i915_psr psr;

	struct i915_gpu_error gpu_error;

	struct drm_i915_gem_object *vlv_pctx;

	/* list of fbdev register on this device */
	struct intel_fbdev *fbdev;
	struct work_struct fbdev_suspend_work;

	struct drm_property *broadcast_rgb_property;
	struct drm_property *force_audio_property;

	/* hda/i915 audio component */
	struct i915_audio_component *audio_component;
	bool audio_component_registered;
	/**
	 * av_mutex - mutex for audio/video sync
	 *
	 */
	struct mutex av_mutex;

	struct {
		struct list_head list;
		struct llist_head free_list;
		struct work_struct free_work;

		/* The hw wants to have a stable context identifier for the
		 * lifetime of the context (for OA, PASID, faults, etc).
		 * This is limited in execlists to 21 bits.
		 */
		struct ida hw_ida;
#define KLP_MAX_CONTEXT_HW_ID (1<<21) /* exclusive */
	} contexts;

	u32 fdi_rx_config;

	/* Shadow for DISPLAY_PHY_CONTROL which can't be safely read */
	u32 chv_phy_control;
	/*
	 * Shadows for CHV DPLL_MD regs to keep the state
	 * checker somewhat working in the presence hardware
	 * crappiness (can't read out DPLL_MD for pipes B & C).
	 */
	u32 chv_dpll_md[I915_MAX_PIPES];
	u32 bxt_phy_grc;

	u32 suspend_count;
	bool power_domains_suspended;
	struct i915_suspend_saved_registers regfile;
	struct vlv_s0ix_state vlv_s0ix_state;

	enum {
		I915_SAGV_UNKNOWN = 0,
		I915_SAGV_DISABLED,
		I915_SAGV_ENABLED,
		I915_SAGV_NOT_CONTROLLED
	} sagv_status;

	struct {
		/*
		 * Raw watermark latency values:
		 * in 0.1us units for WM0,
		 * in 0.5us units for WM1+.
		 */
		/* primary */
		uint16_t pri_latency[5];
		/* sprite */
		uint16_t spr_latency[5];
		/* cursor */
		uint16_t cur_latency[5];
		/*
		 * Raw watermark memory latency values
		 * for SKL for all 8 levels
		 * in 1us units.
		 */
		uint16_t skl_latency[8];

		/* current hardware state */
		union {
			struct ilk_wm_values hw;
			struct skl_wm_values skl_hw;
			struct vlv_wm_values vlv;
			struct g4x_wm_values g4x;
		};

		uint8_t max_level;

		/*
		 * Should be held around atomic WM register writing; also
		 * protects * intel_crtc->wm.active and
		 * cstate->wm.need_postvbl_update.
		 */
		struct mutex wm_mutex;

		/*
		 * Set during HW readout of watermarks/DDB.  Some platforms
		 * need to know when we're still using BIOS-provided values
		 * (which we don't fully trust).
		 */
		bool distrust_bios_wm;
	} wm;

	struct i915_runtime_pm runtime_pm;

	struct {
		bool initialized;

		struct kobject *metrics_kobj;
		struct ctl_table_header *sysctl_header;

		/*
		 * Lock associated with adding/modifying/removing OA configs
		 * in dev_priv->perf.metrics_idr.
		 */
		struct mutex metrics_lock;

		/*
		 * List of dynamic configurations, you need to hold
		 * dev_priv->perf.metrics_lock to access it.
		 */
		struct idr metrics_idr;

		/*
		 * Lock associated with anything below within this structure
		 * except exclusive_stream.
		 */
		struct mutex lock;
		struct list_head streams;

		struct {
			/*
			 * The stream currently using the OA unit. If accessed
			 * outside a syscall associated to its file
			 * descriptor, you need to hold
			 * dev_priv->drm.struct_mutex.
			 */
			struct i915_perf_stream *exclusive_stream;

			u32 specific_ctx_id;

			struct hrtimer poll_check_timer;
			wait_queue_head_t poll_wq;
			bool pollin;

			/**
			 * For rate limiting any notifications of spurious
			 * invalid OA reports
			 */
			struct ratelimit_state spurious_report_rs;

			bool periodic;
			int period_exponent;

			struct i915_oa_config test_config;

			struct {
				struct i915_vma *vma;
				u8 *vaddr;
				u32 last_ctx_id;
				int format;
				int format_size;

				/**
				 * Locks reads and writes to all head/tail state
				 *
				 * Consider: the head and tail pointer state
				 * needs to be read consistently from a hrtimer
				 * callback (atomic context) and read() fop
				 * (user context) with tail pointer updates
				 * happening in atomic context and head updates
				 * in user context and the (unlikely)
				 * possibility of read() errors needing to
				 * reset all head/tail state.
				 *
				 * Note: Contention or performance aren't
				 * currently a significant concern here
				 * considering the relatively low frequency of
				 * hrtimer callbacks (5ms period) and that
				 * reads typically only happen in response to a
				 * hrtimer event and likely complete before the
				 * next callback.
				 *
				 * Note: This lock is not held *while* reading
				 * and copying data to userspace so the value
				 * of head observed in htrimer callbacks won't
				 * represent any partial consumption of data.
				 */
				spinlock_t ptr_lock;

				/**
				 * One 'aging' tail pointer and one 'aged'
				 * tail pointer ready to used for reading.
				 *
				 * Initial values of 0xffffffff are invalid
				 * and imply that an update is required
				 * (and should be ignored by an attempted
				 * read)
				 */
				struct {
					u32 offset;
				} tails[2];

				/**
				 * Index for the aged tail ready to read()
				 * data up to.
				 */
				unsigned int aged_tail_idx;

				/**
				 * A monotonic timestamp for when the current
				 * aging tail pointer was read; used to
				 * determine when it is old enough to trust.
				 */
				u64 aging_timestamp;

				/**
				 * Although we can always read back the head
				 * pointer register, we prefer to avoid
				 * trusting the HW state, just to avoid any
				 * risk that some hardware condition could
				 * somehow bump the head pointer unpredictably
				 * and cause us to forward the wrong OA buffer
				 * data to userspace.
				 */
				u32 head;
			} oa_buffer;

			u32 gen7_latched_oastatus1;
			u32 ctx_oactxctrl_offset;
			u32 ctx_flexeu0_offset;

			/**
			 * The RPT_ID/reason field for Gen8+ includes a bit
			 * to determine if the CTX ID in the report is valid
			 * but the specific bit differs between Gen 8 and 9
			 */
			u32 gen8_valid_ctx_bit;

			struct i915_oa_ops ops;
			const struct i915_oa_format *oa_formats;
		} oa;
	} perf;

	/* Abstract the submission mechanism (legacy ringbuffer or execlists) away */
	struct {
		void (*resume)(struct drm_i915_private *);
		void (*cleanup_engine)(struct intel_engine_cs *engine);

		struct list_head timelines;
		struct i915_gem_timeline global_timeline;
		u32 active_requests;

		/**
		 * Is the GPU currently considered idle, or busy executing
		 * userspace requests? Whilst idle, we allow runtime power
		 * management to power down the hardware and display clocks.
		 * In order to reduce the effect on performance, there
		 * is a slight delay before we do so.
		 */
		bool awake;

		/**
		 * We leave the user IRQ off as much as possible,
		 * but this means that requests will finish and never
		 * be retired once the system goes idle. Set a timer to
		 * fire periodically while the ring is running. When it
		 * fires, go retire requests.
		 */
		struct delayed_work retire_work;

		/**
		 * When we detect an idle GPU, we want to turn on
		 * powersaving features. So once we see that there
		 * are no more requests outstanding and no more
		 * arrive within a small period of time, we fire
		 * off the idle_work.
		 */
		struct delayed_work idle_work;

		ktime_t last_init_time;
	} gt;

	/* perform PHY state sanity checks? */
	bool chv_phy_assert[2];

	bool ipc_enabled;

	/* Used to save the pipe-to-encoder mapping for audio */
	struct intel_encoder *av_enc_map[I915_MAX_PIPES];

	/* necessary resource sharing with HDMI LPE audio driver. */
	struct {
		struct platform_device *platdev;
		int	irq;
	} lpe_audio;

	/*
	 * NOTE: This is the dri1/ums dungeon, don't add stuff here. Your patch
	 * will be rejected. Instead look for a better place.
	 */
};


/* from drivers/gpu/drm/i915/gvt/interrupt.h */
enum intel_gvt_event_type {
	RCS_MI_USER_INTERRUPT = 0,
	RCS_DEBUG,
	RCS_MMIO_SYNC_FLUSH,
	RCS_CMD_STREAMER_ERR,
	RCS_PIPE_CONTROL,
	RCS_L3_PARITY_ERR,
	RCS_WATCHDOG_EXCEEDED,
	RCS_PAGE_DIRECTORY_FAULT,
	RCS_AS_CONTEXT_SWITCH,
	RCS_MONITOR_BUFF_HALF_FULL,

	VCS_MI_USER_INTERRUPT,
	VCS_MMIO_SYNC_FLUSH,
	VCS_CMD_STREAMER_ERR,
	VCS_MI_FLUSH_DW,
	VCS_WATCHDOG_EXCEEDED,
	VCS_PAGE_DIRECTORY_FAULT,
	VCS_AS_CONTEXT_SWITCH,

	VCS2_MI_USER_INTERRUPT,
	VCS2_MI_FLUSH_DW,
	VCS2_AS_CONTEXT_SWITCH,

	BCS_MI_USER_INTERRUPT,
	BCS_MMIO_SYNC_FLUSH,
	BCS_CMD_STREAMER_ERR,
	BCS_MI_FLUSH_DW,
	BCS_PAGE_DIRECTORY_FAULT,
	BCS_AS_CONTEXT_SWITCH,

	VECS_MI_USER_INTERRUPT,
	VECS_MI_FLUSH_DW,
	VECS_AS_CONTEXT_SWITCH,

	PIPE_A_FIFO_UNDERRUN,
	PIPE_B_FIFO_UNDERRUN,
	PIPE_A_CRC_ERR,
	PIPE_B_CRC_ERR,
	PIPE_A_CRC_DONE,
	PIPE_B_CRC_DONE,
	PIPE_A_ODD_FIELD,
	PIPE_B_ODD_FIELD,
	PIPE_A_EVEN_FIELD,
	PIPE_B_EVEN_FIELD,
	PIPE_A_LINE_COMPARE,
	PIPE_B_LINE_COMPARE,
	PIPE_C_LINE_COMPARE,
	PIPE_A_VBLANK,
	PIPE_B_VBLANK,
	PIPE_C_VBLANK,
	PIPE_A_VSYNC,
	PIPE_B_VSYNC,
	PIPE_C_VSYNC,
	PRIMARY_A_FLIP_DONE,
	PRIMARY_B_FLIP_DONE,
	PRIMARY_C_FLIP_DONE,
	SPRITE_A_FLIP_DONE,
	SPRITE_B_FLIP_DONE,
	SPRITE_C_FLIP_DONE,

	PCU_THERMAL,
	PCU_PCODE2DRIVER_MAILBOX,

	DPST_PHASE_IN,
	DPST_HISTOGRAM,
	GSE,
	DP_A_HOTPLUG,
	AUX_CHANNEL_A,
	PERF_COUNTER,
	POISON,
	GTT_FAULT,
	ERROR_INTERRUPT_COMBINED,

	FDI_RX_INTERRUPTS_TRANSCODER_A,
	AUDIO_CP_CHANGE_TRANSCODER_A,
	AUDIO_CP_REQUEST_TRANSCODER_A,
	FDI_RX_INTERRUPTS_TRANSCODER_B,
	AUDIO_CP_CHANGE_TRANSCODER_B,
	AUDIO_CP_REQUEST_TRANSCODER_B,
	FDI_RX_INTERRUPTS_TRANSCODER_C,
	AUDIO_CP_CHANGE_TRANSCODER_C,
	AUDIO_CP_REQUEST_TRANSCODER_C,
	ERR_AND_DBG,
	GMBUS,
	SDVO_B_HOTPLUG,
	CRT_HOTPLUG,
	DP_B_HOTPLUG,
	DP_C_HOTPLUG,
	DP_D_HOTPLUG,
	AUX_CHANNEL_B,
	AUX_CHANNEL_C,
	AUX_CHANNEL_D,
	AUDIO_POWER_STATE_CHANGE_B,
	AUDIO_POWER_STATE_CHANGE_C,
	AUDIO_POWER_STATE_CHANGE_D,

	INTEL_GVT_EVENT_RESERVED,
	INTEL_GVT_EVENT_MAX,
};

struct intel_gvt_irq;
struct intel_gvt;
struct intel_vgpu;

typedef void (*gvt_event_virt_handler_t)(struct intel_gvt_irq *irq,
	enum intel_gvt_event_type event, struct intel_vgpu *vgpu);

enum intel_gvt_irq_type {
	INTEL_GVT_IRQ_INFO_GT,
	INTEL_GVT_IRQ_INFO_DPY,
	INTEL_GVT_IRQ_INFO_PCH,
	INTEL_GVT_IRQ_INFO_PM,

	INTEL_GVT_IRQ_INFO_MASTER,
	INTEL_GVT_IRQ_INFO_GT0,
	INTEL_GVT_IRQ_INFO_GT1,
	INTEL_GVT_IRQ_INFO_GT2,
	INTEL_GVT_IRQ_INFO_GT3,
	INTEL_GVT_IRQ_INFO_DE_PIPE_A,
	INTEL_GVT_IRQ_INFO_DE_PIPE_B,
	INTEL_GVT_IRQ_INFO_DE_PIPE_C,
	INTEL_GVT_IRQ_INFO_DE_PORT,
	INTEL_GVT_IRQ_INFO_DE_MISC,
	INTEL_GVT_IRQ_INFO_AUD,
	INTEL_GVT_IRQ_INFO_PCU,

	INTEL_GVT_IRQ_INFO_MAX,
};

struct intel_gvt_event_info {
	int bit;				/* map to register bit */
	int policy;				/* forwarding policy */
	struct intel_gvt_irq_info *info;	/* register info */
	gvt_event_virt_handler_t v_handler;	/* for v_event */
};

struct intel_gvt_vblank_timer {
	struct hrtimer timer;
	u64 period;
};

struct intel_gvt_irq {
	struct intel_gvt_irq_ops *ops;
	struct intel_gvt_irq_info *info[INTEL_GVT_IRQ_INFO_MAX];
	DECLARE_BITMAP(irq_info_bitmap, INTEL_GVT_IRQ_INFO_MAX);
	struct intel_gvt_event_info events[INTEL_GVT_EVENT_MAX];
	DECLARE_BITMAP(pending_events, INTEL_GVT_EVENT_MAX);
	struct intel_gvt_irq_map *irq_map;
	struct intel_gvt_vblank_timer vblank_timer;
};


/* from drivers/gpu/drm/i915/gvt/gtt.h */
struct intel_vgpu_mm;

#define KLP_INTEL_GVT_GTT_HASH_BITS 8

struct intel_gvt_gtt {
	struct intel_gvt_gtt_pte_ops *pte_ops;
	struct intel_gvt_gtt_gma_ops *gma_ops;
	int (*mm_alloc_page_table)(struct intel_vgpu_mm *mm);
	void (*mm_free_page_table)(struct intel_vgpu_mm *mm);
	struct list_head oos_page_use_list_head;
	struct list_head oos_page_free_list_head;
	struct list_head mm_lru_list_head;

	struct page *scratch_page;
	unsigned long scratch_mfn;
};

typedef enum {
	GTT_TYPE_INVALID = -1,

	GTT_TYPE_GGTT_PTE,

	GTT_TYPE_PPGTT_PTE_4K_ENTRY,
	GTT_TYPE_PPGTT_PTE_2M_ENTRY,
	GTT_TYPE_PPGTT_PTE_1G_ENTRY,

	GTT_TYPE_PPGTT_PTE_ENTRY,

	GTT_TYPE_PPGTT_PDE_ENTRY,
	GTT_TYPE_PPGTT_PDP_ENTRY,
	GTT_TYPE_PPGTT_PML4_ENTRY,

	GTT_TYPE_PPGTT_ROOT_ENTRY,

	GTT_TYPE_PPGTT_ROOT_L3_ENTRY,
	GTT_TYPE_PPGTT_ROOT_L4_ENTRY,

	GTT_TYPE_PPGTT_ENTRY,

	GTT_TYPE_PPGTT_PTE_PT,
	GTT_TYPE_PPGTT_PDE_PT,
	GTT_TYPE_PPGTT_PDP_PT,
	GTT_TYPE_PPGTT_PML4_PT,

	GTT_TYPE_MAX,
} intel_gvt_gtt_type_t;

struct intel_vgpu_scratch_pt {
	struct page *page;
	unsigned long page_mfn;
};

struct intel_vgpu_gtt {
	struct intel_vgpu_mm *ggtt_mm;
	unsigned long active_ppgtt_mm_bitmap;
	struct list_head mm_list_head;
	DECLARE_HASHTABLE(shadow_page_hash_table, KLP_INTEL_GVT_GTT_HASH_BITS);
	DECLARE_HASHTABLE(tracked_guest_page_hash_table, KLP_INTEL_GVT_GTT_HASH_BITS);
	atomic_t n_tracked_guest_page;
	struct list_head oos_page_list_head;
	struct list_head post_shadow_list_head;
	struct intel_vgpu_scratch_pt scratch_pt[GTT_TYPE_MAX];
};


/* from drivers/gpu/drm/i915/gvt/reg.h */
#define KLP_INTEL_GVT_OPREGION_PAGES	2


/* from drivers/gpu/drm/i915/gvt/edid.h */
enum gmbus_cycle_type {
	GMBUS_NOCYCLE	= 0x0,
	NIDX_NS_W	= 0x1,
	IDX_NS_W	= 0x3,
	GMBUS_STOP	= 0x4,
	NIDX_STOP	= 0x5,
	IDX_STOP	= 0x7
};

enum gvt_gmbus_phase {
	GMBUS_IDLE_PHASE = 0,
	GMBUS_DATA_PHASE,
	GMBUS_WAIT_PHASE,
	//GMBUS_STOP_PHASE,
	GMBUS_MAX_PHASE
};

struct intel_vgpu_i2c_gmbus {
	unsigned int total_byte_count; /* from GMBUS1 */
	enum gmbus_cycle_type cycle_type;
	enum gvt_gmbus_phase phase;
};

struct intel_vgpu_i2c_aux_ch {
	bool i2c_over_aux_ch;
	bool aux_ch_mot;
};

enum i2c_state {
	I2C_NOT_SPECIFIED = 0,
	I2C_GMBUS = 1,
	I2C_AUX_CH = 2
};

struct intel_vgpu_i2c_edid {
	enum i2c_state state;

	unsigned int port;
	bool slave_selected;
	bool edid_available;
	unsigned int current_edid_read;

	struct intel_vgpu_i2c_gmbus gmbus;
	struct intel_vgpu_i2c_aux_ch aux_ch;
};


/* from drivers/gpu/drm/i915/gvt/display.h */
#define KLP_SBI_REG_MAX	20

struct intel_vgpu_sbi_register {
	unsigned int offset;
	u32 value;
};

struct intel_vgpu_sbi {
	int number;
	struct intel_vgpu_sbi_register registers[KLP_SBI_REG_MAX];
};

struct intel_vgpu_port {
	/* per display EDID information */
	struct intel_vgpu_edid_data *edid;
	/* per display DPCD information */
	struct intel_vgpu_dpcd_data *dpcd;
	int type;
};


/* from drivers/gpu/drm/i915/gvt/execlist.h */
struct execlist_ctx_descriptor_format {
	union {
		u32 ldw;
		struct {
			u32 valid                  : 1;
			u32 force_pd_restore       : 1;
			u32 force_restore          : 1;
			u32 addressing_mode        : 2;
			u32 llc_coherency          : 1;
			u32 fault_handling         : 2;
			u32 privilege_access       : 1;
			u32 reserved               : 3;
			u32 lrca                   : 20;
		};
	};
	union {
		u32 udw;
		u32 context_id;
	};
};

struct intel_vgpu_elsp_dwords {
	u32 data[4];
	u32 index;
};

struct intel_vgpu_execlist_slot {
	struct execlist_ctx_descriptor_format ctx[2];
	u32 index;
};

struct intel_vgpu_execlist {
	struct intel_vgpu_execlist_slot slot[2];
	struct intel_vgpu_execlist_slot *running_slot;
	struct intel_vgpu_execlist_slot *pending_slot;
	struct execlist_ctx_descriptor_format *running_context;
	int ring_id;
	struct intel_vgpu *vgpu;
	struct intel_vgpu_elsp_dwords elsp_dwords;
};


/* from drivers/gpu/drm/i915/gvt/scheduler.h */
struct intel_gvt_workload_scheduler {
	struct intel_vgpu *current_vgpu;
	struct intel_vgpu *next_vgpu;
	struct intel_vgpu_workload *current_workload[KLP_I915_NUM_ENGINES];
	bool need_reschedule;

	spinlock_t mmio_context_lock;
	/* can be null when owner is host */
	struct intel_vgpu *engine_owner[KLP_I915_NUM_ENGINES];

	wait_queue_head_t workload_complete_wq;
	struct task_struct *thread[KLP_I915_NUM_ENGINES];
	wait_queue_head_t waitq[KLP_I915_NUM_ENGINES];

	void *sched_data;
	struct intel_gvt_sched_policy_ops *sched_ops;
};


/* from drivers/gpu/drm/i915/gvt/cmd_parser.h */
#define KLP_GVT_CMD_HASH_BITS 7


/* from drivers/gpu/drm/i915/gvt/gvt.h */
struct intel_gvt_device_info {
	u32 max_support_vgpus;
	u32 cfg_space_size;
	u32 mmio_size;
	u32 mmio_bar;
	unsigned long msi_cap_offset;
	u32 gtt_start_offset;
	u32 gtt_entry_size;
	u32 gtt_entry_size_shift;
	int gmadr_bytes_in_cmd;
	u32 max_surface_size;
};

struct intel_vgpu_gm {
	u64 aperture_sz;
	u64 hidden_sz;
	struct drm_mm_node low_gm_node;
	struct drm_mm_node high_gm_node;
};

#define KLP_INTEL_GVT_MAX_NUM_FENCES 32

struct intel_vgpu_fence {
	struct drm_i915_fence_reg *regs[KLP_INTEL_GVT_MAX_NUM_FENCES];
	u32 base;
	u32 size;
};

struct intel_vgpu_mmio {
	void *vreg;
	void *sreg;
	bool disable_warn_untrack;
};

#define KLP_INTEL_GVT_MAX_BAR_NUM 4

struct intel_vgpu_pci_bar {
	u64 size;
	bool tracked;
};

struct intel_vgpu_cfg_space {
	unsigned char virtual_cfg_space[PCI_CFG_SPACE_EXP_SIZE];
	struct intel_vgpu_pci_bar bar[KLP_INTEL_GVT_MAX_BAR_NUM];
};

#define KLP_INTEL_GVT_MAX_PIPE 4

struct intel_vgpu_irq {
	bool irq_warn_once[INTEL_GVT_EVENT_MAX];
	DECLARE_BITMAP(flip_done_event[KLP_INTEL_GVT_MAX_PIPE],
		       INTEL_GVT_EVENT_MAX);
};

struct intel_vgpu_opregion {
	bool mapped;
	void *va;
	u32 gfn[KLP_INTEL_GVT_OPREGION_PAGES];
};

#define KLP_INTEL_GVT_MAX_PORT 5

struct intel_vgpu_display {
	struct intel_vgpu_i2c_edid i2c_edid;
	struct intel_vgpu_port ports[KLP_INTEL_GVT_MAX_PORT];
	struct intel_vgpu_sbi sbi;
};

struct vgpu_sched_ctl {
	int weight;
};

struct intel_vgpu_submission {
	struct intel_vgpu_execlist execlist[KLP_I915_NUM_ENGINES];
	struct list_head workload_q_head[KLP_I915_NUM_ENGINES];
	struct kmem_cache *workloads;
	atomic_t running_workload_num;
	struct i915_gem_context *shadow_ctx;
	DECLARE_BITMAP(shadow_ctx_desc_updated, KLP_I915_NUM_ENGINES);
	DECLARE_BITMAP(tlb_handle_pending, KLP_I915_NUM_ENGINES);
	void *ring_scan_buffer[KLP_I915_NUM_ENGINES];
	int ring_scan_buffer_size[KLP_I915_NUM_ENGINES];
	const struct intel_vgpu_submission_ops *ops;
	int virtual_submission_interface;
	bool active;
};

struct intel_vgpu {
	struct intel_gvt *gvt;
	int id;
	unsigned long handle; /* vGPU handle used by hypervisor MPT modules */
	bool active;
	bool pv_notified;
	bool failsafe;
	unsigned int resetting_eng;
	void *sched_data;
	struct vgpu_sched_ctl sched_ctl;

	struct intel_vgpu_fence fence;
	struct intel_vgpu_gm gm;
	struct intel_vgpu_cfg_space cfg_space;
	struct intel_vgpu_mmio mmio;
	struct intel_vgpu_irq irq;
	struct intel_vgpu_gtt gtt;
	struct intel_vgpu_opregion opregion;
	struct intel_vgpu_display display;
	struct intel_vgpu_submission submission;
	u32 hws_pga[KLP_I915_NUM_ENGINES];

	struct dentry *debugfs;

#if IS_ENABLED(CONFIG_DRM_I915_GVT_KVMGT)
	struct {
		struct mdev_device *mdev;
		struct vfio_region *region;
		int num_regions;
		struct eventfd_ctx *intx_trigger;
		struct eventfd_ctx *msi_trigger;
		struct rb_root cache;
		struct mutex cache_lock;
		struct notifier_block iommu_notifier;
		struct notifier_block group_notifier;
		struct kvm *kvm;
		struct work_struct release_work;
		atomic_t released;
	} vdev;
#endif
};

struct intel_gvt_gm {
	unsigned long vgpu_allocated_low_gm_size;
	unsigned long vgpu_allocated_high_gm_size;
};

struct intel_gvt_fence {
	unsigned long vgpu_allocated_fence_num;
};

#define KLP_INTEL_GVT_MMIO_HASH_BITS 11

struct intel_gvt_mmio {
	u8 *mmio_attribute;
/* Register contains RO bits */
#define KLP_F_RO		(1 << 0)
/* Register contains graphics address */
#define KLP_F_GMADR		(1 << 1)
/* Mode mask registers with high 16 bits as the mask bits */
#define KLP_F_MODE_MASK	(1 << 2)
/* This reg can be accessed by GPU commands */
#define KLP_F_CMD_ACCESS	(1 << 3)
/* This reg has been accessed by a VM */
#define KLP_F_ACCESSED	(1 << 4)
/* This reg has been accessed through GPU commands */
#define KLP_F_CMD_ACCESSED	(1 << 5)
/* This reg could be accessed by unaligned address */
#define KLP_F_UNALIGN	(1 << 6)

	struct gvt_mmio_block *mmio_block;
	unsigned int num_mmio_block;

	DECLARE_HASHTABLE(mmio_info_table, KLP_INTEL_GVT_MMIO_HASH_BITS);
	unsigned long num_tracked_mmio;
};

struct intel_gvt_firmware {
	void *cfg_space;
	void *mmio;
	bool firmware_loaded;
};

struct intel_gvt {
	struct mutex lock;
	struct drm_i915_private *dev_priv;
	struct idr vgpu_idr;	/* vGPU IDR pool */

	struct intel_gvt_device_info device_info;
	struct intel_gvt_gm gm;
	struct intel_gvt_fence fence;
	struct intel_gvt_mmio mmio;
	struct intel_gvt_firmware firmware;
	struct intel_gvt_irq irq;
	struct intel_gvt_gtt gtt;
	struct intel_gvt_workload_scheduler scheduler;
	struct notifier_block shadow_ctx_notifier_block[KLP_I915_NUM_ENGINES];
	DECLARE_HASHTABLE(cmd_table, KLP_GVT_CMD_HASH_BITS);
	struct intel_vgpu_type *types;
	unsigned int num_types;
	struct intel_vgpu *idle_vgpu;

	struct task_struct *service_thread;
	wait_queue_head_t service_thread_wq;
	unsigned long service_request;

	struct engine_mmio *engine_mmio_list;

	struct dentry *debugfs_root;
};

#define klp_gvt_aperture_pa_base(gvt) (gvt->dev_priv->ggtt.gmadr.start)

#define klp_vgpu_aperture_offset(vgpu)	((vgpu)->gm.low_gm_node.start)

#define klp_vgpu_aperture_sz(vgpu)		((vgpu)->gm.aperture_sz)


/* from drivers/gpu/drm/i915/gvt/kvmgt.c */
#define KLP_VFIO_PCI_OFFSET_SHIFT   40

/* inlined */
static inline bool klp_intel_vgpu_in_aperture(struct intel_vgpu *vgpu,
					      uint64_t off)
{
	return off >= klp_vgpu_aperture_offset(vgpu) &&
	       off < klp_vgpu_aperture_offset(vgpu) + klp_vgpu_aperture_sz(vgpu);
}

/* patched */
int klp_intel_vgpu_mmap(struct mdev_device *mdev, struct vm_area_struct *vma)
{
	unsigned int index;
	u64 virtaddr;
	/*
	 * Fix CVE-2019-11085
	 *  -1 line, +1 line
	 */
	unsigned long req_size, pgoff, req_start;
	pgprot_t pg_prot;
	struct intel_vgpu *vgpu = klp_mdev_get_drvdata(mdev);

	index = vma->vm_pgoff >> (KLP_VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT);
	if (index >= VFIO_PCI_ROM_REGION_INDEX)
		return -EINVAL;

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;
	if ((vma->vm_flags & VM_SHARED) == 0)
		return -EINVAL;
	if (index != VFIO_PCI_BAR2_REGION_INDEX)
		return -EINVAL;

	pg_prot = vma->vm_page_prot;
	virtaddr = vma->vm_start;
	req_size = vma->vm_end - vma->vm_start;
	/*
	 * Fix CVE-2019-11085
	 *  -1 line, +11 lines
	 */
	pgoff = vma->vm_pgoff &
		((1U << (KLP_VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1);
	req_start = pgoff << PAGE_SHIFT;

	if (!klp_intel_vgpu_in_aperture(vgpu, req_start))
		return -EINVAL;
	if (req_start + req_size >
	    klp_vgpu_aperture_offset(vgpu) + klp_vgpu_aperture_sz(vgpu))
		return -EINVAL;

	pgoff = (klp_gvt_aperture_pa_base(vgpu->gvt) >> PAGE_SHIFT) + pgoff;

	return remap_pfn_range(vma, virtaddr, pgoff, req_size, pg_prot);
}



static int livepatch_bsc1135280_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1135280_module_nb = {
	.notifier_call = livepatch_bsc1135280_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1135280_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1135280_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1135280_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1135280_module_nb);
}

#endif /* IS_ENABLED(CONFIG_DRM_I915_GVT_KVMGT) */

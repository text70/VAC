#ifndef _VAC_IOCTL_H
#define _VAC_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define VAC_IOC_MAGIC  'V'
#define VAC_MAX_PROCS  2048
#define VAC_MAX_COMM   16
#define VAC_READ_SIZE  256

/* Capability flags returned by VAC_IOCTL_FILL */
#define VAC_CAP_PROC_LIST     (1u << 0)
#define VAC_CAP_READ_MEM      (1u << 1)
#define VAC_CAP_PROC_NAME     (1u << 2)
#define VAC_CAP_PROTECT       (1u << 3)

/* Single process entry */
struct vac_proc_entry {
	__u32 pid;
	__u32 ppid;
	__u8  comm[VAC_MAX_COMM];
} __attribute__((packed));

/* Process list — user allocates, kernel fills */
struct vac_proc_list {
	__u32 count;
	struct vac_proc_entry entries[VAC_MAX_PROCS];
} __attribute__((packed));

/* Read process memory */
struct vac_read_mem {
	__u32 pid;
	__u64 address;
	__u32 size;
	__u8  data[VAC_READ_SIZE];
	__u32 bytes_read;
} __attribute__((packed));

/* Get process command name */
struct vac_proc_name {
	__u32 pid;
	__u8  comm[VAC_MAX_COMM];
} __attribute__((packed));

/*
 * IOCTL numbers.
 *
 * Note: vac_proc_list (49156 bytes) exceeds the 14-bit size field in _IOR/_IOW,
 * so we use _IO (no size encoding) and handle copy_to_user manually.
 * The small structs (vac_read_mem = 276, vac_proc_name = 20) fit in 14 bits.
 */
#define VAC_IOCTL_FILL        _IOR(VAC_IOC_MAGIC, 0, __u32)        /* size=4 */
#define VAC_IOCTL_PROC_LIST   _IO(VAC_IOC_MAGIC, 1)                /* large struct, manual copy */
#define VAC_IOCTL_READ_MEM    _IOWR(VAC_IOC_MAGIC, 2, struct vac_read_mem)  /* size=276 */
#define VAC_IOCTL_PROC_NAME   _IOWR(VAC_IOC_MAGIC, 3, struct vac_proc_name)  /* size=20 */

#endif

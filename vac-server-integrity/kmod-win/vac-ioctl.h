#ifndef _VAC_IOCTL_WIN_H
#define _VAC_IOCTL_WIN_H

/*
 * Windows kernel driver IOCTL definitions.
 * Mirrors kmod/vac-ioctl.h with identical struct layouts,
 * but uses CTL_CODE() (Windows encoding) instead of _IOR/_IOWR/_IO (Linux).
 *
 * Build with WDK. Include: ntddk.h, wdm.h
 */

#pragma pack(push, 1)

#define VAC_MAX_PROCS  2048
#define VAC_MAX_COMM   16
#define VAC_READ_SIZE  256

/* Capability flags */
#define VAC_CAP_PROC_LIST     (1u << 0)
#define VAC_CAP_READ_MEM      (1u << 1)
#define VAC_CAP_PROC_NAME     (1u << 2)
#define VAC_CAP_PROTECT       (1u << 3)

/* Single process entry */
typedef struct _VAC_PROC_ENTRY {
    ULONG pid;
    ULONG ppid;
    UCHAR comm[VAC_MAX_COMM];
} VAC_PROC_ENTRY, *PVAC_PROC_ENTRY;

/* Process list */
typedef struct _VAC_PROC_LIST {
    ULONG count;
    VAC_PROC_ENTRY entries[VAC_MAX_PROCS];
} VAC_PROC_LIST, *PVAC_PROC_LIST;

/* Read process memory */
typedef struct _VAC_READ_MEM {
    ULONG pid;
    ULONG64 address;
    ULONG size;
    UCHAR data[VAC_READ_SIZE];
    ULONG bytes_read;
} VAC_READ_MEM, *PVAC_READ_MEM;

/* Get process name */
typedef struct _VAC_PROC_NAME {
    ULONG pid;
    UCHAR comm[VAC_MAX_COMM];
} VAC_PROC_NAME, *PVAC_PROC_NAME;

#pragma pack(pop)

/*
 * IOCTL codes — Windows CTL_CODE encoding:
 *   CTL_CODE(DeviceType, Function, Method, Access)
 *   = (DeviceType<<16) | (Access<<14) | (Function<<2) | Method
 */
#define VAC_IOCTL_FILL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define VAC_IOCTL_PROC_LIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define VAC_IOCTL_READ_MEM \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define VAC_IOCTL_PROC_NAME \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif
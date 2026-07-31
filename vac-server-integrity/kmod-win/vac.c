/*
 * vac.sys — Windows kernel driver for VAC anti-cheat.
 *
 * WDM driver exposing \Device\Vac + \DosDevices\Vac (-> \\.\Vac).
 * Handles 4 IOCTLs mirroring the Linux kmod/vac.c interface:
 *   FILL, PROC_LIST, READ_MEM, PROC_NAME
 *
 * Build: WDK 10/11 from an x64 command prompt:
 *   cl /nologo /c /O2 /GS- /W4 /WX /I"%WDK_INC%" vac.c
 *   link /nologo /driver /subsystem:native /entry:DriverEntry
 *       vac.obj ntoskrnl.lib
 */

#include <ntddk.h>
#include "vac-ioctl.h"

/* ------------------------------------------------------------------ */
/*  Device name / link                                                 */
/* ------------------------------------------------------------------ */
#define DEVICE_NAME          L"\\Device\\Vac"
#define SYMBOLIC_LINK_NAME   L"\\DosDevices\\Vac"
#define POOL_TAG             'caV'   /* "Vac" backwards */

/* ------------------------------------------------------------------ */
/*  Forward declarations                                               */
/* ------------------------------------------------------------------ */
DRIVER_UNLOAD    VacUnload;
DRIVER_DISPATCH  VacCreateClose;
DRIVER_DISPATCH  VacDeviceControl;

/* ------------------------------------------------------------------ */
/*  Helper: find EPROCESS by PID                                       */
/* ------------------------------------------------------------------ */
static PEPROCESS
VacLookupProcess(
    ULONG pid
)
{
    PEPROCESS process = NULL;
    if (pid == 0) {
        return PsGetCurrentProcess();
    }
    NTSTATUS status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)pid,
        &process
    );
    if (!NT_SUCCESS(status)) {
        return NULL;
    }
    return process;
}

/* ------------------------------------------------------------------ */
/*  IOCTL handlers                                                     */
/* ------------------------------------------------------------------ */

static NTSTATUS
VacIoctlFill(
    PVOID  SystemBuffer,
    ULONG  OutputBufferLength,
    PULONG BytesReturned
)
{
    ULONG caps = VAC_CAP_PROC_LIST | VAC_CAP_READ_MEM | VAC_CAP_PROC_NAME;
    UNREFERENCED_PARAMETER(OutputBufferLength);

    *(PULONG)SystemBuffer = caps;
    *BytesReturned = sizeof(ULONG);
    return STATUS_SUCCESS;
}

static NTSTATUS
VacIoctlProcList(
    PVOID  SystemBuffer,
    ULONG  OutputBufferLength,
    PULONG BytesReturned
)
{
    NTSTATUS status;
    PVAC_PROC_LIST list = (PVAC_PROC_LIST)SystemBuffer;
    ULONG count = 0, i = 0;
    PSYSTEM_PROCESS_INFORMATION spi = NULL;
    ULONG buf_size = 256 * 1024;   /* 256 KB for process info */
    PVOID buf = NULL;

    if (OutputBufferLength < sizeof(VAC_PROC_LIST)) {
        *BytesReturned = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Allocate temp buffer for ZwQuerySystemInformation */
    buf = ExAllocatePoolWithTag(PagedPool, buf_size, POOL_TAG);
    if (!buf) {
        *BytesReturned = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(
        SystemProcessInformation,
        buf,
        buf_size,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buf, POOL_TAG);
        *BytesReturned = 0;
        return status;
    }

    spi = (PSYSTEM_PROCESS_INFORMATION)buf;

    while (count < VAC_MAX_PROCS) {
        ULONG pid = (ULONG)(ULONG_PTR)spi->UniqueProcessId;
        ULONG ppid = (ULONG)(ULONG_PTR)spi->InheritedFromUniqueProcessId;

        list->entries[count].pid  = pid;
        list->entries[count].ppid = ppid;

        /* Copy process name from UNICODE_STRING -> ASCII comm */
        RtlZeroMemory(list->entries[count].comm, VAC_MAX_COMM);
        if (spi->ImageName.Buffer && spi->ImageName.Length > 0) {
            ANSI_STRING ansi;
            UNICODE_STRING uni;
            uni.Buffer        = spi->ImageName.Buffer;
            uni.Length        = spi->ImageName.Length;
            uni.MaximumLength = spi->ImageName.MaximumLength;
            if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansi, &uni, TRUE))) {
                ULONG copy_len = ansi.Length;
                if (copy_len > VAC_MAX_COMM - 1)
                    copy_len = VAC_MAX_COMM - 1;
                RtlCopyMemory(list->entries[count].comm, ansi.Buffer, copy_len);
                RtlFreeAnsiString(&ansi);
            }
        }

        count++;
        if (spi->NextEntryOffset == 0)
            break;
        spi = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)spi + spi->NextEntryOffset);
    }

    ExFreePoolWithTag(buf, POOL_TAG);

    list->count = count;
    *BytesReturned = sizeof(ULONG) + count * sizeof(VAC_PROC_ENTRY);
    return STATUS_SUCCESS;
}

static NTSTATUS
VacIoctlReadMem(
    PVOID  SystemBuffer,
    ULONG  InputBufferLength,
    ULONG  OutputBufferLength,
    PULONG BytesReturned
)
{
    PVAC_READ_MEM rm = (PVAC_READ_MEM)SystemBuffer;
    PEPROCESS target;
    SIZE_T bytes_copied = 0;

    if (InputBufferLength < sizeof(VAC_READ_MEM) ||
        OutputBufferLength < sizeof(VAC_READ_MEM)) {
        *BytesReturned = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (rm->size > VAC_READ_SIZE)
        rm->size = VAC_READ_SIZE;

    target = VacLookupProcess(rm->pid);
    if (!target) {
        rm->bytes_read = 0;
        *BytesReturned = sizeof(VAC_READ_MEM);
        return STATUS_NOT_FOUND;
    }

    NTSTATUS status = MmCopyVirtualMemory(
        target,                     /* source process   */
        (PVOID)(ULONG_PTR)rm->address,
        PsGetCurrentProcess(),      /* target process   */
        rm->data,
        rm->size,
        KernelMode,
        &bytes_copied
    );

    if (NT_SUCCESS(status)) {
        rm->bytes_read = (ULONG)bytes_copied;
    } else {
        rm->bytes_read = 0;
    }

    ObDereferenceObject(target);
    *BytesReturned = sizeof(VAC_READ_MEM);
    return status;
}

static NTSTATUS
VacIoctlProcName(
    PVOID  SystemBuffer,
    ULONG  InputBufferLength,
    ULONG  OutputBufferLength,
    PULONG BytesReturned
)
{
    PVAC_PROC_NAME pn = (PVAC_PROC_NAME)SystemBuffer;
    PEPROCESS target;

    if (InputBufferLength < sizeof(VAC_PROC_NAME) ||
        OutputBufferLength < sizeof(VAC_PROC_NAME)) {
        *BytesReturned = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    target = VacLookupProcess(pn->pid);
    if (!target) {
        RtlZeroMemory(pn->comm, VAC_MAX_COMM);
        *BytesReturned = sizeof(VAC_PROC_NAME);
        return STATUS_NOT_FOUND;
    }

    PCHAR img_name = PsGetProcessImageFileName(target);
    if (img_name) {
        ULONG len = (ULONG)strlen(img_name);
        if (len > VAC_MAX_COMM - 1)
            len = VAC_MAX_COMM - 1;
        RtlCopyMemory(pn->comm, img_name, len);
        pn->comm[len] = '\0';
    } else {
        RtlZeroMemory(pn->comm, VAC_MAX_COMM);
    }

    ObDereferenceObject(target);
    *BytesReturned = sizeof(VAC_PROC_NAME);
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  IRP dispatch                                                       */
/* ------------------------------------------------------------------ */

NTSTATUS
VacCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
VacDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION  stack = IoGetCurrentIrpStackLocation(Irp);
    PVOID   buf   = Irp->AssociatedIrp.SystemBuffer;
    ULONG   in_len  = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG   out_len = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG   code    = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG   returned = 0;
    NTSTATUS status;

    switch (code) {
    case VAC_IOCTL_FILL:
        status = VacIoctlFill(buf, out_len, &returned);
        break;

    case VAC_IOCTL_PROC_LIST:
        status = VacIoctlProcList(buf, out_len, &returned);
        break;

    case VAC_IOCTL_READ_MEM:
        status = VacIoctlReadMem(buf, in_len, out_len, &returned);
        break;

    case VAC_IOCTL_PROC_NAME:
        status = VacIoctlProcName(buf, in_len, out_len, &returned);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        returned = 0;
        break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = returned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ------------------------------------------------------------------ */
/*  Driver entry / unload                                              */
/* ------------------------------------------------------------------ */

VOID
VacUnload(
    PDEVICE_OBJECT DeviceObject
)
{
    UNICODE_STRING symLink;

    RtlInitUnicodeString(&symLink, SYMBOLIC_LINK_NAME);
    IoDeleteSymbolicLink(&symLink);

    if (DeviceObject)
        IoDeleteDevice(DeviceObject);
}

NTSTATUS
DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    UNICODE_STRING devName, symLink;
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&devName, DEVICE_NAME);
    RtlInitUnicodeString(&symLink, SYMBOLIC_LINK_NAME);

    /* Create the device object */
    status = IoCreateDevice(
        DriverObject,
        0,                          /* DeviceExtensionSize */
        &devName,
        FILE_DEVICE_UNKNOWN,
        0,                          /* DeviceCharacteristics */
        FALSE,                      /* Exclusive */
        &deviceObject
    );
    if (!NT_SUCCESS(status))
        return status;

    /* Allow all access (administrator required to open anyway) */
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    /* Dispatch table */
    DriverObject->DriverUnload                          = VacUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]          = VacCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]           = VacCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = VacDeviceControl;

    /* Buffered I/O for METHOD_BUFFERED */
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}
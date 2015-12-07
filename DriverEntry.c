#include <ntifs.h>
#include "VMX.h"

// void
// DriverUnload(
// 	PDRIVER_OBJECT pDriverObject
// 	)
// {
// 	KdPrint(("[HyperVisor] DriverUnload~\n"));
// }

NTSTATUS
DriverEntry(
	PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegistryPath
	)
{
    ULONG sum_cpu;
    KAFFINITY ActiveProcessors, t;
    ULONG i = 0;

    KdPrint(("\n[HyperVisor] DriverEntry~\n"));

    if (!__Support_VMX())
    {
        KdPrint(("No Support VMX!\n"));
        return STATUS_UNSUCCESSFUL;
    }

	//pDriverObject->DriverUnload = DriverUnload;

    sum_cpu = KeQueryActiveProcessorCount(&ActiveProcessors);  // KeQueryActiveProcessorCount >= vista

    while (sum_cpu--)
    {
        #define MAX_PROCID (sizeof(ULONG) << 3)

        for ( ; i < MAX_PROCID; i++ )
        {
            t = ActiveProcessors & (((ULONG_PTR)1)<<i);
            if (t)
            {
                KeSetSystemAffinityThreadEx(t);  // KeSetSystemAffinityThreadEx >= vista
                GetGuestState();
                VmcsInit();
                break;
            }
        }
    }

	return STATUS_SUCCESS;
}

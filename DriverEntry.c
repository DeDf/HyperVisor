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

    KdPrint(("[HyperVisor] DriverEntry~\n"));

	//pDriverObject->DriverUnload = DriverUnload;

    sum_cpu = KeQueryActiveProcessorCount(&ActiveProcessors);  // KeQueryActiveProcessorCount >= vista

    while (sum_cpu--)
    {
        for ( ; i < MAX_PROCID; i++ )
        {
            t = ActiveProcessors & (1<<i);
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

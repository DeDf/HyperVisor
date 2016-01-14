#include <ntifs.h>
#include "VMX.h"

NTSTATUS
DriverEntry(
	PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegistryPath
	)
{
    ULONG sum_cpu;
    KAFFINITY ActiveProcessors, t;
    ULONG_PTR guest_rsp;
    ULONG_PTR guest_rip;
    ULONG i = 0;

    KdPrint(("\n[HyperVisor] DriverEntry~\n"));

    if (!__Support_VMX())
    {
        KdPrint(("[HyperVisor] No Support VMX!\n"));
        return STATUS_UNSUCCESSFUL;
    }

    sum_cpu = KeQueryActiveProcessorCount(&ActiveProcessors);  // KeQueryActiveProcessorCount >= vista

    while (sum_cpu--)
    {
        #define MAX_PROCID (sizeof(ULONG) << 3)

        for ( ; i < MAX_PROCID; i++ )
        {
            t = ActiveProcessors & (1i64<<i);
            if (t)
            {
                KeSetSystemAffinityThreadEx(t);  // KeSetSystemAffinityThreadEx >= vista
                GetGuestState();
                get_guest_exit(&guest_rsp, &guest_rip);  // 获取VmcsInit的下一条指令
                VmcsInit(guest_rsp, guest_rip);
                i++;
                break;
            }
        }
    }

	return STATUS_SUCCESS;
}

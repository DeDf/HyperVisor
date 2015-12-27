
#include "HyperVisor.h"

//////////////////////////////////////////////////////////////////////

extern void __hv_cpuid();
extern void __hv_invd();
extern void __hv_rdtsc();
extern ULONG_PTR __hv_rdmsr();
extern void __hv_wrmsr();

extern void __hv_null();
VMTrap g_VmExit_funcs[MAX_HV_CALLBACK] = {__hv_null};

//////////////////////////////////////////////////////////////////////

void fakeRDMSR( __inout ULONG_PTR reg[REG_COUNT] );

void VmExit_funcs_init()
{
    static int Vmfuncs_inited = 0;
    if (!Vmfuncs_inited)
    {
        Vmfuncs_inited = 1;
        g_VmExit_funcs[VMX_EXIT_CPUID]  = __hv_cpuid;
        g_VmExit_funcs[VMX_EXIT_INVD]   = __hv_invd;
        g_VmExit_funcs[VMX_EXIT_RDTSC]  = __hv_rdtsc;
        g_VmExit_funcs[VMX_EXIT_CRX_MOVE] = HandleCrxAccess;
        g_VmExit_funcs[VMX_EXIT_RDMSR]  = fakeRDMSR;
        g_VmExit_funcs[VMX_EXIT_WRMSR]  = __hv_wrmsr;
    }
}

//////////////////////////////////////////////////////////////////////

UCHAR
HVEntryPoint( 
	__inout ULONG_PTR reg[REG_COUNT]
	)
{
	UCHAR status;
    //
	ULONG_PTR ExitReason;
    ULONG_PTR ExitInstructionLength;
    ULONG_PTR GuestEIP;
    
    status = __vmx_vmread(VMX_VMCS32_RO_EXIT_REASON, &ExitReason);

    status = __vmx_vmread(VMX_VMCS64_GUEST_RIP, &GuestEIP);
	status = __vmx_vmread(VMX_VMCS32_RO_EXIT_INSTR_LENGTH, &ExitInstructionLength);
	status = __vmx_vmwrite(VMX_VMCS64_GUEST_RIP, GuestEIP + ExitInstructionLength);

    if((ExitReason > VMX_EXIT_VMCALL) && (ExitReason <= VMX_EXIT_VMXON))
    {
        ULONG_PTR GuestRFLAGS;
        status = __vmx_vmread(VMX_VMCS_GUEST_RFLAGS, &GuestRFLAGS);
        status = __vmx_vmwrite(VMX_VMCS_GUEST_RFLAGS, GuestRFLAGS & (~0x8d5) | 0x1);
    }

    g_VmExit_funcs[ExitReason](reg);

    return status;
}

void
HandleCrxAccess( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	UCHAR status;
	ULONG_PTR ExitQualification;

    status = __vmx_vmread(VMX_VMCS_RO_EXIT_QUALIFICATION, &ExitQualification);
        if (status) return;

	{
		ULONG_PTR cr      = (ExitQualification & 0x0000000F);
		ULONG_PTR operand = (ExitQualification & 0x00000040) >> 6;

		if (3 == cr && 0 == operand)
		{
			ULONG_PTR acess = (ExitQualification & 0x00000030) >> 4;
			ULONG_PTR r64 = (ExitQualification & 0x00000F00) >> 8;

			r64 = r64 < REG_X86_COUNT ? 
				((~r64) + REG_X86_COUNT) : 
			(REG_X86_COUNT + (~(r64 - REG_X86_COUNT)) + REG_X86_COUNT);

			if (1 == acess)
			{
				ULONG_PTR cr3;
                status = __vmx_vmread(VMX_VMCS64_GUEST_CR3, &cr3);
				if (!status)
					reg[r64] = cr3;
			}
			else if (0 == acess)
			{
				__vmx_vmwrite(VMX_VMCS64_GUEST_CR3, reg[r64]);

				//handle pagefault via VMX_EXIT_EPT_VIOLATION
				__vmx_vmwrite(VMX_VMCS_CTRL_EPTP_FULL, reg[r64]);
				__vmx_vmwrite(VMX_VMCS_CTRL_EPTP_HIGH, reg[r64] >> 32);
			}
		}
	}
}

void 
fakeRDMSR( 
    __inout ULONG_PTR reg[REG_COUNT]
    )
{
    ULONG_PTR syscall;
    if (IA64_SYSENTER_EIP == reg[RCX])
    {
        syscall = g_GuestState.SEIP;
    }
    else
    {
        syscall = __hv_rdmsr(reg[RCX]);
    }

    reg[RAX] = syscall;
    reg[RDX] = (syscall >> (sizeof(ULONG) << 3));
}
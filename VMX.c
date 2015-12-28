
#include "VMX.h"

GUEST_STATE	g_GuestState;

extern void  hv_exit();

//////////////////////////////////////////////////////////////////////

ULONG32 VmxAdjustControls (
                           ULONG32 Ctl,
                           ULONG32 Msr
                           )
{
    LARGE_INTEGER MsrValue;

    MsrValue.QuadPart = __readmsr (Msr);
    Ctl &= MsrValue.HighPart;     /* bit == 0 in high word ==> must be zero */
    Ctl |= MsrValue.LowPart;      /* bit == 1 in low word  ==> must be one  */
    return Ctl;
}

void
GetGuestState()
{
    PHYSICAL_ADDRESS HighestAcceptableAddress;
    HighestAcceptableAddress.QuadPart = 0xFFFFFFFF00000000;

    g_GuestState.CR0 = __readcr0();
    g_GuestState.CR3 = __readcr3();
    g_GuestState.CR4 = __readcr4() | CR4_VMXE;
    g_GuestState.RFLAGS = __readeflags();

    g_GuestState.Cs = __readcs();
    g_GuestState.Ds = __readds();
    g_GuestState.Es = __reades();
    g_GuestState.Ss = __readss();
    g_GuestState.Fs = __readfs();
    g_GuestState.Gs = __readgs();
    g_GuestState.Ldtr = __sldt();
    g_GuestState.Tr = __str();

    __sgdt(&(g_GuestState.Gdtr));
    __sidt(&(g_GuestState.Idtr));

    g_GuestState.S_CS = __readmsr(IA32_SYSENTER_CS);
    g_GuestState.SEIP = __readmsr(IA64_SYSENTER_EIP);
    g_GuestState.SESP = __readmsr(IA32_SYSENTER_ESP);

    g_GuestState.VMXON = MmAllocateNonCachedMemory(PAGE_SIZE);
    RtlZeroMemory(g_GuestState.VMXON, PAGE_SIZE);

    g_GuestState.VMCS  = MmAllocateNonCachedMemory(PAGE_SIZE);
    RtlZeroMemory(g_GuestState.VMCS,  PAGE_SIZE);

    g_GuestState.hvStack =        // 分配的是非页面内存, 且保证在物理内存中是连续的, MmFreeContiguousMemory
        MmAllocateContiguousMemory(PAGE_SIZE * 2, HighestAcceptableAddress);
    RtlZeroMemory(g_GuestState.hvStack, PAGE_SIZE * 2);
}

void
SetCRx()
{
    __vmx_vmwrite(VMX_VMCS_CTRL_CR4_MASK, X86_CR4_VMXE);
    __vmx_vmwrite(VMX_VMCS_CTRL_CR4_READ_SHADOW, 0);

    __vmx_vmwrite(VMX_VMCS64_GUEST_CR0, g_GuestState.CR0);
    __vmx_vmwrite(VMX_VMCS64_GUEST_CR3, g_GuestState.CR3);
    __vmx_vmwrite(VMX_VMCS64_GUEST_CR4, g_GuestState.CR4);
    //
    __vmx_vmwrite(VMX_VMCS64_GUEST_DR7, 0x400 );

    __vmx_vmwrite(VMX_VMCS_HOST_CR0, g_GuestState.CR0);
    __vmx_vmwrite(VMX_VMCS_HOST_CR3, g_GuestState.CR3);
    __vmx_vmwrite(VMX_VMCS_HOST_CR4, g_GuestState.CR4);
}

void
SetDT()
{
    __vmx_vmwrite(VMX_VMCS64_GUEST_GDTR_BASE,  g_GuestState.Gdtr.base);
    __vmx_vmwrite(VMX_VMCS32_GUEST_GDTR_LIMIT, g_GuestState.Gdtr.limit);
    __vmx_vmwrite(VMX_VMCS64_GUEST_IDTR_BASE,  g_GuestState.Idtr.base);
    __vmx_vmwrite(VMX_VMCS32_GUEST_IDTR_LIMIT, g_GuestState.Idtr.limit);
    
    __vmx_vmwrite(VMX_VMCS_HOST_GDTR_BASE, g_GuestState.Gdtr.base);
    __vmx_vmwrite(VMX_VMCS_HOST_IDTR_BASE, g_GuestState.Idtr.base);
}

void
SetSysCall()
{
    __vmx_vmwrite(GUEST_SYSENTER_CS,  g_GuestState.S_CS);
    __vmx_vmwrite(GUEST_SYSENTER_ESP, g_GuestState.SESP);
    __vmx_vmwrite(GUEST_SYSENTER_EIP, g_GuestState.SEIP);

    __vmx_vmwrite(HOST_SYSENTER_CS,   g_GuestState.S_CS);
    __vmx_vmwrite(HOST_SYSENTER_EIP,  g_GuestState.SEIP);
    __vmx_vmwrite(HOST_SYSENTER_ESP,  g_GuestState.SESP);
}

void 
GetSegmentDescriptor(
                     __out SEGMENT_SELECTOR* segSel, 
                     __in ULONG_PTR selector 
                     )
{
    SEGMENT_DESCRIPTOR* seg = (SEGMENT_DESCRIPTOR *)((PUCHAR)g_GuestState.Gdtr.base + (selector >> 3) * 8);

    segSel->selector = selector;
    segSel->limit    = (ULONG)(seg->LimitLow | seg->LimitHigh << 16);
    segSel->base     = seg->BaseLow | seg->BaseMid << 16 | seg->BaseHigh << 24;
    segSel->attributes = (USHORT)(seg->AttributesLow | seg->AttributesHigh << 8);

    if (!(seg->AttributesLow & NORMAL))  // is TSS or HV_CALLBACK ? Yes save the base high part
        segSel->base |= ((*(PULONG64) ((PUCHAR)seg + 8)) << 32);

#define	IS_GRANULARITY_4KB  (1 << 0xB)

    if (segSel->attributes & IS_GRANULARITY_4KB)
        segSel->limit = (segSel->limit << 12) | 0xFFF;

    segSel->rights =
        (segSel->selector ? (((PUCHAR) &segSel->attributes)[0] + (((PUCHAR) &segSel->attributes)[1] << 12)) : 0x10000);
}

UCHAR
SetSegSelector(  // done!
               __in ULONG_PTR Selector,
               __in ULONG_PTR VMCS_Index
               )
{
    UCHAR status;
    size_t i = (VMCS_Index - VMX_VMCS16_GUEST_FIELD_ES);

    SEGMENT_SELECTOR seg_sel;
    GetSegmentDescriptor(&seg_sel, Selector);

    status = __vmx_vmwrite(VMX_VMCS16_GUEST_FIELD_ES         + i, Selector);        if (status) return status;
    status = __vmx_vmwrite(VMX_VMCS32_GUEST_ES_LIMIT         + i, seg_sel.limit);   if (status) return status;
    status = __vmx_vmwrite(VMX_VMCS32_GUEST_ES_ACCESS_RIGHTS + i, seg_sel.rights);  if (status) return status;

    return status;
}

void
SetSegSelectors()
{
    SEGMENT_SELECTOR seg_sel;

    // GUEST
    __vmx_vmwrite (VMX_VMCS64_GUEST_CS_BASE, 0);
    __vmx_vmwrite (VMX_VMCS64_GUEST_DS_BASE, 0);
    __vmx_vmwrite (VMX_VMCS64_GUEST_ES_BASE, 0);
    __vmx_vmwrite (VMX_VMCS64_GUEST_SS_BASE, 0);
    __vmx_vmwrite (VMX_VMCS64_GUEST_FS_BASE, __readmsr (IA32_FS_BASE));
    __vmx_vmwrite (VMX_VMCS64_GUEST_GS_BASE, __readmsr (IA32_GS_BASE));
    GetSegmentDescriptor((SEGMENT_SELECTOR *)&seg_sel, g_GuestState.Ldtr);
    __vmx_vmwrite (VMX_VMCS64_GUEST_LDTR_BASE, seg_sel.base);
    GetSegmentDescriptor((SEGMENT_SELECTOR *)&seg_sel, g_GuestState.Tr);
    __vmx_vmwrite (VMX_VMCS64_GUEST_TR_BASE, seg_sel.base);

    SetSegSelector(g_GuestState.Cs, VMX_VMCS16_GUEST_FIELD_CS);
    SetSegSelector(g_GuestState.Ds, VMX_VMCS16_GUEST_FIELD_DS);
    SetSegSelector(g_GuestState.Es, VMX_VMCS16_GUEST_FIELD_ES);
    SetSegSelector(g_GuestState.Ss, VMX_VMCS16_GUEST_FIELD_SS);
    SetSegSelector(g_GuestState.Fs, VMX_VMCS16_GUEST_FIELD_FS);
    SetSegSelector(g_GuestState.Gs, VMX_VMCS16_GUEST_FIELD_GS);
    SetSegSelector(g_GuestState.Ldtr, VMX_VMCS16_GUEST_FIELD_LDTR);
    SetSegSelector(g_GuestState.Tr, VMX_VMCS16_GUEST_FIELD_TR);

    // HOST
    // {
    // SELECTORS
    __vmx_vmwrite(VMX_VMCS16_HOST_FIELD_CS, SEG_CODE);
    __vmx_vmwrite(VMX_VMCS16_HOST_FIELD_DS, SEG_DATA);
    __vmx_vmwrite(VMX_VMCS16_HOST_FIELD_ES, SEG_DATA);
    __vmx_vmwrite(VMX_VMCS16_HOST_FIELD_SS, SEG_DATA);
    __vmx_vmwrite(VMX_VMCS16_HOST_FIELD_FS, g_GuestState.Fs & 0xf8);
    __vmx_vmwrite(VMX_VMCS16_HOST_FIELD_GS, g_GuestState.Gs & 0xf8);
    __vmx_vmwrite(VMX_VMCS16_HOST_FIELD_TR, g_GuestState.Tr & 0xf8);

    // BASE
    __vmx_vmwrite (VMX_VMCS_HOST_FS_BASE, __readmsr (IA32_FS_BASE));
    __vmx_vmwrite (VMX_VMCS_HOST_GS_BASE, __readmsr (IA32_GS_BASE));
    __vmx_vmwrite(VMX_VMCS_HOST_TR_BASE, seg_sel.base);
    // }
}

BOOLEAN
VmcsInit(ULONG_PTR guest_rsp, ULONG_PTR guest_rip)
{
    UCHAR status;
    PHYSICAL_ADDRESS addr;
    //
    ULONG_PTR VMCS_revision_id;

    // 检查IA32_FEATURE_CONTROL寄存器的Lock位
    if (!(__readmsr(IA32_FEATURE_CONTROL_CODE) & FEATURE_CONTROL_LOCKED))
    {
        KdPrint(("[HyperVisor] IA32_FEATURE_CONTROL bit[0] = 0!\n"));
        return FALSE;
    }

    // 检查IA32_FEATURE_CONTROL寄存器的Enable VMX outside SMX位
    if (!(__readmsr(IA32_FEATURE_CONTROL_CODE) & FEATURE_CONTROL_VMXON_ENABLED))
    {
        KdPrint(("[HyperVisor] IA32_FEATURE_CONTROL bit[2] = 0!\n"));
        return FALSE;
    }

    guest_rip += 5 * 3;  // 跨过mov, mov, call VmcsInit
    KdPrint(("[HyperVisor] guest RSP:%p, RIP:%p\n", guest_rsp, guest_rip));

    VmExit_funcs_init();

    __writecr4(g_GuestState.CR4);  // 设置CR4_VMXE

    VMCS_revision_id = __readmsr(IA32_VMX_BASIC_MSR_CODE) & 0xffffffff;
    *(PULONG_PTR)(g_GuestState.VMCS)  = VMCS_revision_id;
    *(PULONG_PTR)(g_GuestState.VMXON) = VMCS_revision_id;
    KdPrint(("[HyperVisor] VMCS_revision_id : 0x%x\n", VMCS_revision_id));

    addr = MmGetPhysicalAddress(g_GuestState.VMXON);
	status = __vmx_on(&addr);       if (status) return FALSE;

    addr = MmGetPhysicalAddress(g_GuestState.VMCS);
	status = __vmx_vmclear(&addr);  if (status) return FALSE;
	status = __vmx_vmptrld(&addr);  if (status) return FALSE;

    //GUEST
    __vmx_vmwrite(VMX_VMCS_GUEST_LINK_PTR_FULL, 0xffffffff);
    __vmx_vmwrite(VMX_VMCS_GUEST_LINK_PTR_HIGH, 0xffffffff);

	//GLOBALS
    __vmx_vmwrite(VMX_VMCS_CTRL_PIN_EXEC_CONTROLS,  VmxAdjustControls (0, IA32_VMX_PINBASED_CTLS));
    __vmx_vmwrite(VMX_VMCS_CTRL_PROC_EXEC_CONTROLS, VmxAdjustControls (0, IA32_VMX_PROCBASED_CTLS));
    __vmx_vmwrite(VMX_VMCS_CTRL_EXCEPTION_BITMAP, 0);
    __vmx_vmwrite(VMX_VMCS_CTRL_EXIT_CONTROLS,
                           VmxAdjustControls( VMX_VMCS32_EXIT_ACK_ITR_ON_EXIT | VMX_VMCS32_EXIT_IA32E_MODE, IA32_VMX_EXIT_CTLS));
    __vmx_vmwrite(VMX_VMCS_CTRL_ENTRY_CONTROLS,     VmxAdjustControls (VMX_VMCS32_EXIT_IA32E_MODE, IA32_VMX_ENTRY_CTLS));

    __vmx_vmwrite(VMX_VMCS_CTRL_EXIT_MSR_STORE_COUNT, 0);
    __vmx_vmwrite(VMX_VMCS_CTRL_EXIT_MSR_LOAD_COUNT,  0);
    __vmx_vmwrite(VMX_VMCS_CTRL_ENTRY_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VMX_VMCS_CTRL_ENTRY_IRQ_INFO,       0);   // 设置注入事件的信息
    __vmx_vmwrite(VMX_VMCS32_GUEST_ACTIVITY_STATE,    0);   // 处于正常执行指令状态 

	SetCRx();
	SetDT();
	SetSysCall();
    SetSegSelectors();

    __vmx_vmwrite(VMX_VMCS64_GUEST_RSP, guest_rsp);
    __vmx_vmwrite(VMX_VMCS64_GUEST_RIP, guest_rip);
    __vmx_vmwrite(VMX_VMCS_GUEST_RFLAGS, g_GuestState.RFLAGS);

	__vmx_vmwrite(VMX_VMCS_HOST_RSP, (ULONG_PTR)g_GuestState.hvStack + PAGE_SIZE*2 - 8);
	__vmx_vmwrite(VMX_VMCS_HOST_RIP, hv_exit);

	__vmx_vmlaunch();

	DbgPrint("[HyperVisor] vmlaunch failed!\n");
	__debugbreak();
	return FALSE;
}


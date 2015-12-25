
#include "VMX.h"

GUEST_STATE	g_guestState;

extern void  hv_exit();

//////////////////////////////////////////////////////////////////////

void
GetGuestState()  // done!
{
    PHYSICAL_ADDRESS HighestAcceptableAddress;
    HighestAcceptableAddress.QuadPart = 0xFFFFFFFF00000000;

    g_guestState.CR0 = __readcr0();
    g_guestState.CR3 = __readcr3();
    g_guestState.CR4 = __readcr4();
    g_guestState.RFLAGS = __readeflags();

    g_guestState.Cs = __readcs();
    g_guestState.Ds = __readds();
    g_guestState.Es = __reades();
    g_guestState.Ss = __readss();
    g_guestState.Fs = __readfs();
    g_guestState.Gs = __readgs();
    g_guestState.Ldtr = __sldt();
    g_guestState.Tr = __str();

    __sgdt(&(g_guestState.Gdtr));
    __sidt(&(g_guestState.Idtr));

    g_guestState.SEIP  = __readmsr(IA64_SYSENTER_EIP);
    g_guestState.SESP  = __readmsr(IA32_SYSENTER_ESP);

    g_guestState.VMXON = MmAllocateNonCachedMemory(PAGE_SIZE);
    RtlZeroMemory(g_guestState.VMXON, PAGE_SIZE);

    g_guestState.VMCS  = MmAllocateNonCachedMemory(PAGE_SIZE);
    RtlZeroMemory(g_guestState.VMCS,  PAGE_SIZE);

    g_guestState.hvStack =        // ������Ƿ�ҳ���ڴ棬�ұ�֤�������ڴ�����������,MmFreeContiguousMemory
        MmAllocateContiguousMemory(HYPERVISOR_STACK_PAGE, HighestAcceptableAddress);
    RtlZeroMemory(g_guestState.hvStack, HYPERVISOR_STACK_PAGE);
}

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
SetCRx()
{
    __vmx_vmwrite(VMX_VMCS_CTRL_CR4_MASK, X86_CR4_VMXE);
    __vmx_vmwrite(VMX_VMCS_CTRL_CR4_READ_SHADOW, 0);

    __vmx_vmwrite(VMX_VMCS64_GUEST_CR0, g_guestState.CR0);
    __vmx_vmwrite(VMX_VMCS64_GUEST_CR3, g_guestState.CR3);
    __vmx_vmwrite(VMX_VMCS64_GUEST_CR4, g_guestState.CR4);
    //
    __vmx_vmwrite(VMX_VMCS64_GUEST_DR7, 0x400 );

    __vmx_vmwrite(VMX_VMCS_HOST_CR0, g_guestState.CR0);
    __vmx_vmwrite(VMX_VMCS_HOST_CR3, g_guestState.CR3);
    __vmx_vmwrite(VMX_VMCS_HOST_CR4, g_guestState.CR4);
}

void
SetDT()
{
    SEGMENT_SELECTOR seg_sel;

    __vmx_vmwrite(VMX_VMCS64_GUEST_GDTR_BASE,  g_guestState.Gdtr.base);
    __vmx_vmwrite(VMX_VMCS32_GUEST_GDTR_LIMIT, g_guestState.Gdtr.limit);
    __vmx_vmwrite(VMX_VMCS64_GUEST_IDTR_BASE,  g_guestState.Idtr.base);
    __vmx_vmwrite(VMX_VMCS32_GUEST_IDTR_LIMIT, g_guestState.Idtr.limit);

    GetSegmentDescriptor((SEGMENT_SELECTOR *)&seg_sel, g_guestState.Tr);
    __vmx_vmwrite(VMX_VMCS_HOST_TR_BASE, seg_sel.base);
    __vmx_vmwrite(VMX_VMCS_HOST_GDTR_BASE, g_guestState.Gdtr.base);  // Fix
    __vmx_vmwrite(VMX_VMCS_HOST_IDTR_BASE, g_guestState.Idtr.base);  // Fix
}

BOOLEAN
VmcsInit(ULONG_PTR guest_rsp, ULONG_PTR guest_rip)
{
    UCHAR status;
    PHYSICAL_ADDRESS addr;
    //
    ULONG_PTR VMCS_revision_id;

    // ���IA32_FEATURE_CONTROL�Ĵ�����Lockλ
    if (!(__readmsr(IA32_FEATURE_CONTROL_CODE) & FEATURE_CONTROL_LOCKED))
    {
        KdPrint(("[HyperVisor] IA32_FEATURE_CONTROL bit[0] = 0!\n"));
        return FALSE;
    }

    // ���IA32_FEATURE_CONTROL�Ĵ�����Enable VMX outside SMXλ
    if (!(__readmsr(IA32_FEATURE_CONTROL_CODE) & FEATURE_CONTROL_VMXON_ENABLED))
    {
        KdPrint(("[HyperVisor] IA32_FEATURE_CONTROL bit[2] = 0!\n"));
        return FALSE;
    }

    guest_rip += 5 * 3;  // ���mov, mov, call VmcsInit
    KdPrint(("[HyperVisor] guest RSP:%p, RIP:%p \n", guest_rsp, guest_rip));

    VmExit_funcs_init();
    __writecr4(g_guestState.CR4 | CR4_VMXE);  // ����CR4_VMXE
    VMCS_revision_id = __readmsr(IA32_VMX_BASIC_MSR_CODE) & 0xffffffff;
    *(PULONG_PTR)(g_guestState.VMCS)  = VMCS_revision_id;
    *(PULONG_PTR)(g_guestState.VMXON) = VMCS_revision_id;
    KdPrint(("[HyperVisor] VMCS_revision_id : 0x%x\n", VMCS_revision_id));

    addr = MmGetPhysicalAddress(g_guestState.VMXON);
	status = __vmx_on(&addr);       if (status) return FALSE;

    addr = MmGetPhysicalAddress(g_guestState.VMCS);
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
    __vmx_vmwrite(VMX_VMCS_CTRL_ENTRY_IRQ_INFO,       0);

    __vmx_vmwrite (VMX_VMCS32_GUEST_INTERRUPTIBILITY_STATE, 0);   // ָʾ��ǰ��STI����״̬
    __vmx_vmwrite (VMX_VMCS32_GUEST_ACTIVITY_STATE,         0);   // ��������ִ��ָ��״̬ 

	SetCRx();
	SetDT();
	if (SetSysCall())      return FALSE;
    if (SetSegSelectors()) return FALSE;

    __vmx_vmwrite(VMX_VMCS64_GUEST_RSP, guest_rsp);
    __vmx_vmwrite(VMX_VMCS64_GUEST_RIP, guest_rip);
    __vmx_vmwrite(VMX_VMCS_GUEST_RFLAGS, g_guestState.RFLAGS);

	__vmx_vmwrite(VMX_VMCS_HOST_RSP, (ULONG_PTR)g_guestState.hvStack + PAGE_SIZE - 1);
	__vmx_vmwrite(VMX_VMCS_HOST_RIP, hv_exit);

	//descriptor tables
	DbgPrint("\nidtr base %p",  g_guestState.Idtr.base);
	DbgPrint("\nidtr limit %p", g_guestState.Idtr.limit);
	DbgPrint("\ngdtr base %p",  g_guestState.Gdtr.base);
	DbgPrint("\ngdtr limit %p", g_guestState.Gdtr.limit);

	//SELECTORS
	DbgPrint("\ncs  %p", g_guestState.Cs);
	DbgPrint("\nds  %p", g_guestState.Ds);
	DbgPrint("\nes  %p", g_guestState.Es);
	DbgPrint("\nss  %p", g_guestState.Ss);	
	DbgPrint("\nfs  %p", g_guestState.Fs);
	DbgPrint("\ngs  %p", g_guestState.Gs);	
	DbgPrint("\nldtr %p", g_guestState.Ldtr);
	DbgPrint("\ntr  %p", g_guestState.Tr);

	__vmx_vmlaunch();

	DbgPrint("[HyperVisor] vmlaunch failed!\n");
	__debugbreak();
	return FALSE;
}

typedef struct _CS_STAR
{
    union
    {
        ULONG_PTR Value;
        struct
        {
            ULONG_PTR Reserved :0x20;
            ULONG_PTR SyscallCs:0x10;
            ULONG_PTR SysretCs :0x10;
        };
    };
} CS_STAR;

UCHAR
SetSysCall()  // done!
{
	UCHAR status;
	CS_STAR cs = { __readmsr(IA32_STAR) };

    status = __vmx_vmwrite(VMX_VMCS32_GUEST_SYSENTER_CS,  cs.SyscallCs & QWORD_LIMIT);    if (status) return status;
    status = __vmx_vmwrite(VMX_VMCS64_GUEST_SYSENTER_ESP, (ULONG_PTR)g_guestState.SESP);  if (status) return status;
    status = __vmx_vmwrite(VMX_VMCS64_GUEST_SYSENTER_EIP, (ULONG_PTR)g_guestState.SEIP);  if (status) return status;

    status = __vmx_vmwrite(VMX_VMCS32_HOST_SYSENTER_CS,   cs.SyscallCs & QWORD_LIMIT);    if (status) return status;
    status = __vmx_vmwrite(VMX_VMCS_HOST_SYSENTER_EIP,    (ULONG_PTR)g_guestState.SEIP);  if (status) return status;
    status = __vmx_vmwrite(VMX_VMCS_HOST_SYSENTER_ESP,    (ULONG_PTR)g_guestState.SESP);  if (status) return status;

	return status;
}

void 
GetSegmentDescriptor(  // done!
	__out SEGMENT_SELECTOR* segSel, 
	__in ULONG_PTR selector 
	)
{
	SEGMENT_DESCRIPTOR* seg = (SEGMENT_DESCRIPTOR *)((PUCHAR)g_guestState.Gdtr.base + (selector >> 3) * 8);

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
    status = __vmx_vmwrite(VMX_VMCS64_GUEST_ES_BASE          + i, seg_sel.base);    if (status) return status;
    status = __vmx_vmwrite(VMX_VMCS32_GUEST_ES_LIMIT         + i, seg_sel.limit);   if (status) return status;
    status = __vmx_vmwrite(VMX_VMCS32_GUEST_ES_ACCESS_RIGHTS + i, seg_sel.rights);  if (status) return status;
	
	return status;
}

UCHAR
SetSegSelectors()  // done!
{
    UCHAR status;

    //SELECTORS
    status = SetSegSelector(g_guestState.Cs, VMX_VMCS16_GUEST_FIELD_CS);     if (status) return status;
    status = SetSegSelector(g_guestState.Ds, VMX_VMCS16_GUEST_FIELD_DS);     if (status) return status;
    status = SetSegSelector(g_guestState.Es, VMX_VMCS16_GUEST_FIELD_ES);     if (status) return status;
    status = SetSegSelector(g_guestState.Ss, VMX_VMCS16_GUEST_FIELD_SS);     if (status) return status;
    status = SetSegSelector(g_guestState.Fs, VMX_VMCS16_GUEST_FIELD_FS);     if (status) return status;
    status = SetSegSelector(g_guestState.Gs, VMX_VMCS16_GUEST_FIELD_GS);     if (status) return status;
    status = SetSegSelector(g_guestState.Ldtr, VMX_VMCS16_GUEST_FIELD_LDTR); if (status) return status;
    status = SetSegSelector(g_guestState.Tr, VMX_VMCS16_GUEST_FIELD_TR);     if (status) return status;

    //HOST
    status = __vmx_vmwrite(VMX_VMCS16_HOST_FIELD_CS, SEG_CODE);              if (status) return status;
    status = __vmx_vmwrite(VMX_VMCS16_HOST_FIELD_DS, SEG_DATA);              if (status) return status;
    status = __vmx_vmwrite(VMX_VMCS16_HOST_FIELD_ES, SEG_DATA);              if (status) return status;
    status = __vmx_vmwrite(VMX_VMCS16_HOST_FIELD_SS, SEG_DATA);              if (status) return status;
    status = __vmx_vmwrite(VMX_VMCS16_HOST_FIELD_FS, g_guestState.Fs & 0xf8);  if (status) return status;
    status = __vmx_vmwrite(VMX_VMCS16_HOST_FIELD_GS, g_guestState.Gs & 0xf8);  if (status) return status;
    status = __vmx_vmwrite(VMX_VMCS16_HOST_FIELD_TR, g_guestState.Tr & 0xf8);  if (status) return status;

    return status;
}

/* MSRs */
#define IA32_FEATURE_CONTROL_CODE               0x03A
#define IA32_SYSENTER_CS                        0x174
#define IA32_SYSENTER_ESP                       0x175
#define IA32_SYSENTER_EIP                       0x176
#define IA32_DEBUGCTL                           0x1D9
#define IA32_VMX_BASIC_MSR_CODE                 0x480
#define IA32_VMX_PINBASED_CTLS                  0x481
#define IA32_VMX_PROCBASED_CTLS                 0x482
#define IA32_VMX_EXIT_CTLS                      0x483
#define IA32_VMX_ENTRY_CTLS                     0x484
#define IA32_VMX_MISC                           0x485
#define IA32_VMX_CR0_FIXED0                     0x486
#define IA32_VMX_CR0_FIXED1                     0x487
#define IA32_VMX_CR4_FIXED0                     0x488
#define IA32_VMX_CR4_FIXED1                     0x489
#define IA32_FS_BASE							0xC0000100
#define IA32_GS_BASE							0xC0000101
#define IA64_SYSENTER_EIP                       0xC0000082
#define IA32_STAR								0xc0000081
#define IA32_FMASK								0xc0000084

#define IA32_TIME_STAMP_COUNTER	 0x10

//HW specific ...
#define MSR_LASTBRANCH_0_FROM_IP 0x40
#define MSR_LASTBRANCH_0_TO_IP   0x60
#define MSR_LASTBRANCH_TOS       0x1C9
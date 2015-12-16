#pragma once

#include "HVCommon.h"
#include "HyperVisor.h"
#include "instrinsics.h"
#include "msr.h"
#include "vmcs.h"

extern GUEST_STATE	g_guestState;

extern BOOLEAN __Support_VMX();

extern
void
get_guest_exit(
               __out ULONG_PTR* guestRip,
               __out ULONG_PTR* guestRsp
               );

void GetGuestState();
BOOLEAN VmcsInit(ULONG_PTR guest_rsp, ULONG_PTR guest_rip);

void 
GetSegmentDescriptor(
                     OUT SEGMENT_SELECTOR* segSel, 
                     ULONG_PTR selector
                     );

UCHAR
SetSegSelector(
               ULONG_PTR segSelector,
               ULONG_PTR segField
               );

UCHAR
SetSegSelectors();

UCHAR
SetCRx();

UCHAR
SetControls();

UCHAR
SetDT();

UCHAR
SetSysCall();

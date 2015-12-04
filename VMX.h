#pragma once

#include "HVCommon.h"

extern GUEST_STATE	g_guestState;

extern BOOLEAN __Support_VMX();

extern
void
__fastcall
get_guest_exit(
               __out ULONG_PTR* guestRip,
               __out ULONG_PTR* guestRsp
               );

void GetGuestState();
BOOLEAN VmcsInit();

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
SetCRx();

UCHAR
SetControls();

UCHAR
SetDT();

UCHAR
SetSysCall();

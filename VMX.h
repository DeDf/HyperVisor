#pragma once

#include "HVCommon.h"

void GetGuestState();
BOOLEAN VmcsInit();

void 
GetSegmentDescriptor(
                     __out SEGMENT_SELECTOR* segSel, 
                     __in ULONG_PTR selector
                     );

UCHAR
SetSegSelector(
               __in ULONG_PTR segSelector,
               __in ULONG_PTR segField
               );

UCHAR
SetCRx();

UCHAR
SetControls();

UCHAR
SetDT();

UCHAR
SetSysCall();

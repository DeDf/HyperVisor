#pragma once

#include "HVCommon.h"
#include "HyperVisor.h"
#include "instrinsics.h"
#include "msr.h"
#include "vmcs.h"

extern GUEST_STATE	g_GuestState;

extern
BOOLEAN
__Support_VMX();

extern
void
get_guest_exit(
               __out ULONG_PTR* guestRip,
               __out ULONG_PTR* guestRsp
               );

void
GetGuestState();

BOOLEAN
VmcsInit(ULONG_PTR guest_rsp, ULONG_PTR guest_rip);

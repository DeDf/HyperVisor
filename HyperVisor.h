#pragma once

#include "HVCommon.h"
#include "vmcs.h"
#include "msr.h"

typedef void (*VMCallback)(
	__inout ULONG_PTR reg[REG_COUNT], 
	__in const void* param
	);

typedef void (*VMTrap)(
	__inout ULONG_PTR reg[REG_COUNT]
	);

UCHAR
HVEntryPoint(
		__inout ULONG_PTR reg[REG_COUNT]
		);

void
HandleCrxAccess(
    __inout ULONG_PTR reg[REG_COUNT]
);
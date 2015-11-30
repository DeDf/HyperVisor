
#ifndef __INSTRINSICS_H__
#define __INSTRINSICS_H__

#include <intrin.h>

EXTERN_C ULONG_PTR __rol(ULONG_PTR val, BYTE rotation);
EXTERN_C ULONG_PTR __ror(ULONG_PTR val, BYTE rotation);

EXTERN_C void __cli();
EXTERN_C void __sti();

EXTERN_C ULONG_PTR __sgdt(__out void * gdtr);
EXTERN_C ULONG_PTR __vmx_call(__in ULONG_PTR);

EXTERN_C ULONG_PTR __readcs();
EXTERN_C ULONG_PTR __readds();
EXTERN_C ULONG_PTR __reades();
EXTERN_C ULONG_PTR __readss();
EXTERN_C ULONG_PTR __readfs();
EXTERN_C ULONG_PTR __readgs();
EXTERN_C ULONG_PTR __sldt();
EXTERN_C ULONG_PTR __str();

EXTERN_C ULONG_PTR __xchgds(__inout ULONG_PTR* ds);
EXTERN_C ULONG_PTR __writeds(__in ULONG_PTR ds);

enum EVmErrors
{
	VM_ERROR_OK = 0,
	VM_ERROR_ERR_INFO_OK,
	VM_ERROR_ERR_INFO_ERR,
};

#define VM_OK(status)         (status == EVmErrors::VM_ERROR_OK)

namespace Instrinsics
{	
	__forceinline
	ULONG_PTR VmRead(
		__in size_t field,
		__inout EVmErrors* err = NULL
		)
	{
		size_t val;
		EVmErrors _err = (EVmErrors)__vmx_vmread(field, &val);

		if (err)
			*err = _err;

		NT_ASSERT(VM_OK(_err));
		return static_cast<ULONG_PTR>(val);
	}

	__forceinline
	__checkReturn
	EVmErrors VmWrite(
		__in size_t field, 
		__inout ULONG_PTR val 
		)
	{
		EVmErrors err = (EVmErrors)__vmx_vmwrite(field, val);
		NT_ASSERT(VM_OK(err));
		return err;
	}
};

#endif //__INSTRINSICS_H__

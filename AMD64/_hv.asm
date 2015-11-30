extrn HVEntryPoint:proc

include .\common.inc

.code

__hv_rdmsr proc
	rdmsr
	vmresume
__hv_rdmsr endp

__hv_wrmsr proc
	wrmsr
	vmresume
__hv_wrmsr endp

__hv_cpuid proc	
	cpuid
	vmresume
__hv_cpuid endp

__hv_invd proc
	invd
	vmresume
__hv_invd endp

__hv_vmcall proc
	vmresume
__hv_vmcall endp

__hv_rdtsc proc
	;rdtsc
	push rcx
	mov rcx, 010h
	rdmsr ;IA32_TIME_STAMP_COUNTER
	pop rcx
	vmresume
__hv_rdtsc endp

__hv_resume proc
	vmresume
__hv_resume endp


hv_exit proc

	pushaq
	call HVEntryPoint
	popaq
	vmresume
	
hv_exit endp

end                 

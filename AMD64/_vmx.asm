.code

__Support_VMX proc
    mov     rax, 1
    cpuid
    bt      ecx, 5
    setc    al
    movzx   rax, al
    ret
__Support_VMX endp

get_guest_exit proc
	lea rax, [rsp + sizeof(QWORD)]
	mov [rcx], rax

	mov rax, [rsp]
	mov [rdx], rax

	xor rax, rax
	ret
get_guest_exit endp

end
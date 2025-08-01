section .data
    wSystemCall         dd 0
    qSyscallInsAdress   dq 0

section .text
    global SetSSn
    global RunSyscall

SetSSn:
    xor eax, eax                    ; eax = 0
    mov [wSystemCall], eax          ; wSystemCall = 0
    mov [qSyscallInsAdress], rax    ; qSyscallInsAdress = 0
    mov eax, ecx                    ; eax = ssn
    mov [wSystemCall], eax          ; wSystemCall = eax = ssn
    mov r8, rdx                     ; r8 = AddressOfASyscallInst
    mov [qSyscallInsAdress], r8     ; qSyscallInsAdress = r8 = AddressOfASyscallInst
    ret

RunSyscall:
    xor r10, r10                    ; r10 = 0
    mov rax, rcx                    ; rax = rcx
    mov r10, rax                    ; r10 = rax = rcx
    mov eax, [wSystemCall]          ; eax = ssn
    jmp Run                         ; execute 'Run'
    xor eax, eax                    ; won't run
    xor rcx, rcx                    ; won't run
    shl r10, 2                      ; won't run
Run:
    jmp [qSyscallInsAdress]
    xor r10, r10                    ; r10 = 0
    mov [qSyscallInsAdress], r10    ; qSyscallInsAdress = 0
    ret
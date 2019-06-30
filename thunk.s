[org 0x00300000]                    ; thunk will be loaded at this address
[bits 64]
push    rbp                         ; save registers that could be used by 32-bit code as well (RBP -> EBP, RBX -> EBX)
push    rbx
mov     [l_rsp], rsp                ; store RSP in reserved memory after the code. We can't use
                                    ; a 64-bit mode register (R8-R15) because even though the program's
                                    ; and the DLL's code is 32 bits, we finally land in the 64-bit kernel
                                    ; through the system call. This means registers R8-R11 could get overwritten.
                                    ; Registers R12-R15 are preserved, but we would need to save them as well =>
                                    ; chicken and egg problem.
push    l_entry                     ; push address of 32-bit code as qword
mov     dword [rsp + 4], 0x23       ; overwrite the high dword with the segment selector
retf                                ; "return" to 32-bit code

l_entry:
[bits 32]
mov     esp, 0x00300000             ; load new stack address - stack for Windows program lives below this thunk
push    ss                          ; set DS to the value of SS (see https://stackoverflow.com/questions/41921711/running-32-bit-code-in-64-bit-process-on-linux-memory-access)
pop     ds
mov     eax, 0x00401000             ; call entry point of Windows program
call    eax
push    0x0                         ; set DS back to 0
pop     ds
push    0x33                        ; push segment selector and address of 64-bit code
push    l_return
retf                                ; "return" to 64-bit code

l_return:
[bits 64]
mov     rsp, [l_rsp]                ; restore RSP
pop     rbx                         ; restore other registers
pop     rbp
ret                                 ; return to WoL

align   8
l_rsp:
dd      0xdeadbeef                  ; reserve memory for RSP
dd      0xdeadbeef
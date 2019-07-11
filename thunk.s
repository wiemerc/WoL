.intel_syntax noprefix
.global entry_point_thunk

.code64
entry_point_thunk:
push    rbp                         # save registers that could be used by 32-bit code as well (RBP -> EBP, RBX -> EBX)
push    rbx
push    r12                         # save R12 because we save RSP in it
mov     r12, rsp                    # We use R12 to save RSP because even though the Windows program's
                                    # and the DLL's code is 32 bits, we finally land in the 64-bit kernel
                                    # through the system call. This means registers R8-R11 could get overwritten.
push    offset l_entry              # push address of 32-bit code as qword
mov     dword ptr [rsp + 4], 0x23   # overwrite the high dword with the segment selector
retf                                # "return" to 32-bit code

l_entry:
.code32
mov     esp, esi                    # load new stack address (2nd argument - stack_addr)
push    ss                          # set DS and ES to the value of SS
pop     ds                          # (see https://stackoverflow.com/questions/41921711/running-32-bit-code-in-64-bit-process-on-linux-memory-access)
push    ss
pop     es
call    edi                         # call entry point of Windows program passed as 1st argument (entry_point)
push    0x0                         # set DS back to 0
pop     ds
push    0x33                        # push segment selector and address of 64-bit code
push    offset l_return
retf                                # "return" to 64-bit code

l_return:
.code64
mov     rsp, r12                    # restore RSP
pop     r12                         # restore other registers
pop     rbx
pop     rbp
ret                                 # return to main()

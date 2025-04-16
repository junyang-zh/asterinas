/* SPDX-License-Identifier: MPL-2.0 */

.text
.global __memcpy_fallible
.code64
__memcpy_fallible: # (dst: *mut u8, src: *const u8, size: usize) -> usize
    mov rcx, rdx        # rcx = size
    test rcx, rcx
    jz .Lexit

    # Step 1: Align destination to 8 bytes
    mov rax, rdi
    mov r8, rsi         # Save src
    mov r9, rcx         # Save size

    mov rdx, rax
    and rdx, 7          # rdx = misalignment
    jz .Laligned

    mov r10, 8
    sub r10, rdx        # r10 = bytes to align
    cmp rcx, r10
    cmova r10, rcx      # if size < r10, copy only size bytes

.Lalign_loop:
1:  mov al, BYTE PTR [rsi]
2:  mov BYTE PTR [rdi], al
    inc rsi
    inc rdi
    dec rcx
    dec r10
    jz .Laligned
    test rcx, rcx
    jz .Lexit
    jmp 1b

.Laligned:
    # Step 2: Bulk copy with movsq
    mov rax, rcx
    shr rax, 3          # rax = number of qwords
    test rax, rax
    jz .Ltail

    push rcx            # Save remaining bytes
    mov rcx, rax
3:  rep movsq
    pop rcx
    and rcx, 7          # rcx = remaining bytes

.Ltail:
    test rcx, rcx
    jz .Lexit
4:  mov al, BYTE PTR [rsi]
5:  mov BYTE PTR [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jnz 4b

.Lexit:
    mov rax, rcx
    ret

.pushsection .ex_table, "a"
    .align 8
    .quad 1b
    .quad .Lexit      # movb (rsi),al fault -> exit
    .quad 2b
    .quad .Lexit      # movb al,(rdi) fault -> exit
    .quad 3b
    .quad .Lexit      # rep movsq fault -> exit
    .quad 4b
    .quad .Lexit      # movb (rsi),al fault -> exit
    .quad 5b
    .quad .Lexit      # movb al,(rdi) fault -> exit
.popsection
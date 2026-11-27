// SPDX-License-Identifier: MPL-2.0

// RV64I memcpy. All wide memory accesses are naturally aligned and lie
// wholly within the requested intervals. Return the original destination.
.section .text.memcpy, "ax", @progbits
.p2align 2
.global memcpy
.global __corten_rv_memcpy
.type memcpy, @function
.type __corten_rv_memcpy, @function
memcpy:
__corten_rv_memcpy:
    mv a3, a0
    li t0, 8
    bltu a2, t0, .Lcopy_tail
    xor t0, a3, a1
    andi t0, t0, 7
    bnez t0, .Lcopy_bytes
.Lcopy_align:
    andi t0, a3, 7
    beqz t0, .Lcopy_wide
    lbu t0, 0(a1)
    sb t0, 0(a3)
    addi a1, a1, 1
    addi a3, a3, 1
    addi a2, a2, -1
    j .Lcopy_align
.Lcopy_wide:
    li t0, 64
    bltu a2, t0, .Lcopy_word
.Lcopy_line:
    ld t1, 0(a1)
    ld t2, 8(a1)
    ld t3, 16(a1)
    ld t4, 24(a1)
    ld t5, 32(a1)
    ld t6, 40(a1)
    ld a4, 48(a1)
    ld a5, 56(a1)
    sd t1, 0(a3)
    sd t2, 8(a3)
    sd t3, 16(a3)
    sd t4, 24(a3)
    sd t5, 32(a3)
    sd t6, 40(a3)
    sd a4, 48(a3)
    sd a5, 56(a3)
    addi a1, a1, 64
    addi a3, a3, 64
    addi a2, a2, -64
    bgeu a2, t0, .Lcopy_line
.Lcopy_word:
    li t0, 8
    bltu a2, t0, .Lcopy_tail
.Lcopy_next_word:
    ld t1, 0(a1)
    sd t1, 0(a3)
    addi a1, a1, 8
    addi a3, a3, 8
    addi a2, a2, -8
    bgeu a2, t0, .Lcopy_next_word
    j .Lcopy_tail
.Lcopy_bytes:
    li t0, 8
.Lcopy_eight:
    lbu t1, 0(a1)
    lbu t2, 1(a1)
    lbu t3, 2(a1)
    lbu t4, 3(a1)
    lbu t5, 4(a1)
    lbu t6, 5(a1)
    lbu a4, 6(a1)
    lbu a5, 7(a1)
    sb t1, 0(a3)
    sb t2, 1(a3)
    sb t3, 2(a3)
    sb t4, 3(a3)
    sb t5, 4(a3)
    sb t6, 5(a3)
    sb a4, 6(a3)
    sb a5, 7(a3)
    addi a1, a1, 8
    addi a3, a3, 8
    addi a2, a2, -8
    bgeu a2, t0, .Lcopy_eight
.Lcopy_tail:
    beqz a2, .Lcopy_done
.Lcopy_byte:
    lbu t1, 0(a1)
    sb t1, 0(a3)
    addi a1, a1, 1
    addi a3, a3, 1
    addi a2, a2, -1
    bnez a2, .Lcopy_byte
.Lcopy_done:
    ret
.size memcpy, .-memcpy
.size __corten_rv_memcpy, .-__corten_rv_memcpy

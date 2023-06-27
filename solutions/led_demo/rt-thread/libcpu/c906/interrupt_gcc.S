/*
 * Copyright (c) 2006-2021, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2018/10/02     Bernard      The first version
 * 2018/12/27     Jesven       Add SMP schedule
 * 2021/02/02     lizhirui     Add userspace support
 * 2021/12/24     JasonHu      Add user setting save/restore
 */

#include "cpuport.h"
#include "encoding.h"
#include "stackframe.h"

  .section      .text.entry
  .align 2
  .global trap_entry
  .extern __stack_cpu0
  .extern get_current_thread_kernel_stack_top

.global rt_hw_context_switch_interrupt_do
rt_hw_context_switch_interrupt_do:

__restore_sp_from_sscratch_interrupt:
    csrr t0, sscratch
    j __move_stack_context_interrupt

__move_stack_context_interrupt:
    mv t1, sp//src
    mv sp, t0//switch stack
    addi sp, sp, -CTX_REG_NR * REGBYTES
    //copy context
    li s0, CTX_REG_NR//cnt
    mv t2, sp//dst

copy_context_loop_interrupt:
    LOAD t0, 0(t1)
    STORE t0, 0(t2)
    addi s0, s0, -1
    addi t1, t1, 8
    addi t2, t2, 8
    bnez s0, copy_context_loop_interrupt

    la    s0, rt_interrupt_from_thread
    LOAD  s1, 0(s0)
    STORE sp, 0(s1)

    la    s0, rt_interrupt_to_thread
    LOAD  s1, 0(s0)
    LOAD  sp, 0(s1)

spurious_interrupt:
    RESTORE_ALL
    sret

.global rt_hw_interrupt_enable
rt_hw_interrupt_enable:
    csrs sstatus, a0    /* restore to old csr */
    jr ra

.global rt_hw_interrupt_disable
rt_hw_interrupt_disable:
    csrrci a0, sstatus, 2   /* clear SIE */
    jr ra

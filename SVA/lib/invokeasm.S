/*===- invokeasm.S - Execution Engine Invoke Assembly Code ----------------===
 * 
 *                     The LLVM Compiler Infrastructure
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This is x64_64 assembly code used by the SVA Execution Engine.
 * It is in AT&T syntax, which means that the source operand is first and
 * the destination operand is second.
 *
 *===----------------------------------------------------------------------===
 */

#include "offsets.h"
#include "sva/cfi.h"

.global sva_invoke
.type sva_invoke, @function

.global sva_invoke_except
.type sva_invoke_except, @function

/*
 * Intrinsic: sva_invoke()
 *
 * Description:
 *  Mimic the LLVM invoke instruction.
 *
 * Inputs:
 *  %rdi - First argument to the function to call
 *  %rsi - Second argument to the function to call
 *  %rdx - Third argument to the function to call
 *  %rcx - Pointer to variable into which the function return value will be
 *         stored
 *  %r8  - Pointer to the function to invoke
 *
 * Return value:
 *  0 - Regular return
 *  1 - Stack was unwound.
 */
sva_invoke:
  /*
   * Create the new invoke frame.  Note that we save call the registers that
   * are saved and restored by callee functions.  This is because callees may
   * not be able to restore these registers in the case of an unwind.
   */
  movq %gs:0x260, %rax
  pushq $INVOKE_NORMAL
  pushq CPU_GIP(%rax)
  pushq %r15
  pushq %r14
  pushq %r13
  pushq %r12
  pushq %rbx
  pushq %rbp

  /*
   * Save the location of the invoke frame into the CPUState.
   */
  movq  %rsp, CPU_GIP(%rax)

  /*
   * Save the pointer to the return value memory location into a callee saved
   * register.
   */
  movq %rcx, %rbx

  /*
   * Call the function.
   */
  callq *%r8
  RETTARGET

  /*
   * Regular Return
   */

  /* Store the return value into the memory location */
  movq %rax, (%rbx)

  /* Restore the saved registers */
  popq %rbp
  popq %rbx
  popq %r12
  popq %r13
  popq %r14
  popq %r15

  /* Remove the saved gip pointer */
  movq %gs:0x260, %rax
  popq CPU_GIP(%rax)

  /* Set the return value */
  movq $0, %rax

  /* Remove the last bit of the invoke frame */
  addq $8, %rsp

  /* Return */
  ret

#if 0
sva_invoke_except:
  movl gip, %esp
  movl $1, %eax
  popl %ebp
  popl %ebx
  popl %esi
  popl %edi
  popl gip
  addl $4, %esp
  ret
#endif

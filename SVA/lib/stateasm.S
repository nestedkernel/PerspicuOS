/*===- stateasm.S - Execution Engine State Manipulation Assembly ------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This is x86_64 assembly code used by the SVA Execution Engine.
 * It is in AT&T syntax, which means that the source operand is first and
 * the destination operand is second.
 *
 *===----------------------------------------------------------------------===
 */

#include "offsets.h"

.data

.text

.global save_integer
.type save_integer, @function

/*
 * Function: save_integer()
 *
 * Description:
 *  This function saves the integer state currently on the processor into a
 *  buffer supplied by the caller.  It is not an intrinsic; sva_swap_integer
 *  will use it to save state.
 *
 * Inputs:
 *  rdi - Pointer to the buffer into which to save the state.
 *
 * Return value:
 *  0  - This was when we saved stated.
 *  ~0 - This is the return value after load_integer() puts this state back on
 *       the processor.
 *
 * Stack Layout:
 *  Pointer to Buffer
 *  Return Pointer
 *  Saved EFLAGS Register
 *  Saved EAX Register
 *
 * TODO:
 *  o I think sva_swap_integer should disable interrupts.
 */
save_integer:
  /*
   * Save the processor state (rflags) register so that we can figure out
   * whether to 
   */
  pushfq

  /* Disable Interrupts */
  cli

#if 0
  /*
   * Verify that the buffer is writable (i.e. fault here before doing anything
   * that might modify the buffer).
   */
  pushq (%rdi)
  popq  (%rdi)
  pushq 56(%rdi)
  popq  56(%rdi)
#endif

  /*
   * Save the segment selector registers and ensure that they are only 16 bits.
   */
  movw %fs,  IC_FS(%rdi)
  movw %gs,  IC_GS(%rdi)
  movw %es,  IC_ES(%rdi)
  andl $0xffff, IC_FS(%rdi)
  andl $0xffff, IC_GS(%rdi)
  andl $0xffff, IC_ES(%rdi)

  /*
   * Save the general purpose registers.
   */
  movq %rsi, IC_RSI(%rdi)

  movq %rax, IC_RAX(%rdi)
  movq %rbx, IC_RBX(%rdi)
  movq %rcx, IC_RCX(%rdi)
  movq %rdx, IC_RDX(%rdi)

  movq %r8,   IC_R8(%rdi)
  movq %r9,   IC_R9(%rdi)
  movq %r10, IC_R10(%rdi)
  movq %r11, IC_R11(%rdi)
  movq %r12, IC_R12(%rdi)
  movq %r13, IC_R13(%rdi)
  movq %r14, IC_R14(%rdi)
  movq %r15, IC_R15(%rdi)

#if 0
  /* Ensure that segments are only 16 bits */
  movw %cs,  60(%rdi)
  movw %ss,  72(%rdi)
  andl $0xffff, 60(%rdi)
  andl $0xffff, 72(%rdi)
#endif

  /* Save the rflags register */
  popq       IC_RFLAGS(%rdi)

  /*
   * Instead of grabbing the current program counter, figure out what it would
   * be after we finish executing this function.
   *
   * In other words, use the return address.
   *
   * Note that load_integer will need to check for a CFI label before using the
   * return address.
   */
  popq  IC_RIP(%rdi)
  movq %rsp, 68(%rdi)
  pushq IC_RIP(%rdi)

  /* Restore interrupts */
  pushq IC_RFLAGS(%rdi)
  popfq

  /* Return a zero to the caller */
  movq $0, %rax

  /* Return to the caller */
  ret


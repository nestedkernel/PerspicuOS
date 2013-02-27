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

#include <sva/cfi.h>

#include "offsets.h"

.data

.text

.global save_integer
.type save_integer, @function

.global load_integer
.type load_integer, @function

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
 */
save_integer:
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

  movq %rbp, IC_RBP(%rdi)
#if 0
  /* Ensure that segments are only 16 bits */
  movw %cs,  60(%rdi)
  movw %ss,  72(%rdi)
  andl $0xffff, 60(%rdi)
  andl $0xffff, 72(%rdi)
#endif

  /* Save the rflags register */
  pushfq
  popq       IC_RFLAGS(%rdi)

  /* Save the stack pointer */
  movq %rsp, IC_RSP(%rdi)

  /*
   * Instead of grabbing the current program counter, figure out what it would
   * be after we finish executing this function.
   *
   * In other words, use the return address.
   *
   * Note that the return address could have been overwritten by another
   * processor between the time sva_swap_integer() was called and the time
   * that we get here.  Therefore, load_integer will need to check for a CFI
   * label before using the return address.
   *
   * Note: Saving the %rip (program counter) is really unnecessary as it is
   *       already saved on the stack and will be vetted by the CFI checks in
   *       load_integer().
   */
  movq (%rsp), %rax
  movq %rax, IC_RIP(%rdi)

  /* Return a zero to the caller */
  movq $0, %rax

  /*
   * Return to the caller
   */
  RETQ

/*
 * Function: load_integer
 *
 * Description:
 *  This function loads the integer state on to the processor from the
 *  buffer supplied by the caller.  It is not an intrinsic; sva_swap_integer
 *  will use it to restore previously saved state.
 *
 * Inputs:
 *  rdi - Pointer to the buffer from which to load the state.
 *
 * Return value:
 *  1 - We unconditionally return this value because, to the caller, it will
 *      appear that we'll wake up and be returning 1 from save_integer.
 *
 */
load_integer:
  /*
   * Restore the traditional registers except for %rax and %rdi:
   *  %rax: This holds the return value, so we don't bother restoring it.
   *  %rcx: This register is used for the CFI jump back to the caller.
   *  %rdi: We wait to restore this register because we're using it to store
   *        the pointer to the integer state buffer.
   */
  movq IC_RBX(%rdi), %rbx
  movq IC_RDX(%rdi), %rdx 
  movq IC_RSI(%rdi), %rsi

  /*
   * Restore them extra 64-bit registers.
   */
  movq  IC_R8(%rdi), %r8
  movq  IC_R9(%rdi), %r9
  movq IC_R10(%rdi), %r10
  movq IC_R11(%rdi), %r11
  movq IC_R12(%rdi), %r12
  movq IC_R13(%rdi), %r13
  movq IC_R14(%rdi), %r14
  movq IC_R15(%rdi), %r15

#if 0
  /* Restore the extra segment registers */
  movw %1, %es 
  movw %1, %ds 
#endif

#if 0
  /* Restore the code and stack segment registers */
  movq 60(%rdi), %cs 
  movq 72(%rdi), %ss 
#endif

  /* Restore the ebp register */
  movq IC_RBP(%rdi), %rbp

  /* Switch to the new stack pointer */
  movq IC_RSP(%rdi), %rsp

  /*
   * Remove the return address from the stack; we won't be using it.
   */
  popq %rcx

#if 0
  /* Put the EFLAGS register on the new stack */
  pushq IC_RFLAGS(%rdi)
#endif

  /*
   * Fetch the correct program counter value for returning from
   * sva_swap_integer() and verify that it is correct.
   */
  movq IC_RIP(%rdi), %rcx
  cmpl  $CHECKLABEL, (%rcx)
  je 1f
  int $3

1:
  /* Restore the %rdi register */
  movq IC_RDI(%rdi), %rdi

  /* Set the return value to 1 */
  movq $1, %rax

#if 0
  /* Restore RFLAGS, potentially re-enabling interrupts */
  popfq
#endif

  /*
   * Return to the caller.
   *
   * TODO: This should do a control-flow integrity label check.
   */
  jmpq *%rcx


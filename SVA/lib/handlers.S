/*===- handlers.S - SVA Execution Engine Assembly --------------------------===
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

/*****************************************************************************
 * Macros
 ****************************************************************************/

/* FreeBSD segment selector for kernel code segment */
#define KERNELCS 0x03

/*****************************************************************************
 * Data Section
 ****************************************************************************/
.data
.comm interrupt_table, 2048

/*****************************************************************************
 * Text Section
 ****************************************************************************/
.text

.global SVAsyscall
.type SVAsyscall, @function

.global SVAsysret
.type SVAsysret, @function

.global secmemtrap
.type secmemtrap, @function

.global trap0
.type trap0, @function

.global secfreetrap
.type secfreetrap, @function

/*
 * Function: saveRegs
 *
 * Description:
 *  This function saves the registers into the interrupt context pointed to
 *  by %rbp.
 */
saveRegs:
  /* Save the registers into the interrupt context */
  movw %fs,  0x10(%rbp)
  movw %gs,  0x12(%rbp)
  movw %es,  0x14(%rbp)

  movq %rdi, 0x18(%rbp)
  movq %rsi, 0x20(%rbp)

  movq %rax, 0x28(%rbp)
  movq %rbx, 0x30(%rbp)
  movq %rcx, 0x38(%rbp)
  movq %rdx, 0x40(%rbp)

  movq %r8,  0x48(%rbp)
  movq %r9,  0x50(%rbp)
  movq %r10, 0x58(%rbp)
  movq %r11, 0x60(%rbp)
  movq %r12, 0x68(%rbp)
  movq %r13, 0x70(%rbp)
  movq %r14, 0x78(%rbp)
  movq %r15, 0x80(%rbp)

  ret

/*
 * Function: restoreRegs
 *
 * Description:
 *  Copy the registers from the interrupt context back on to the processor.
 */
restoreRegs:
#if 0
  movw 0x10(%rbp), %fs
  movw 0x12(%rbp), %gs
  movw 0x14(%rbp), %es
#endif

  movq 0x18(%rbp), %rdi
  movq 0x20(%rbp), %rsi

  movq 0x28(%rbp), %rax
  movq 0x30(%rbp), %rbx
  movq 0x38(%rbp), %rcx
  movq 0x40(%rbp), %rdx

  movq 0x48(%rbp), %r8
  movq 0x50(%rbp), %r9
  movq 0x58(%rbp), %r10
  movq 0x60(%rbp), %r11
  movq 0x68(%rbp), %r12
  movq 0x70(%rbp), %r13
  movq 0x78(%rbp), %r14
  movq 0x80(%rbp), %r15

  ret

trap0:
  /*
   * Determine whether we interrupted user or supervisor mode execution.
   */
  testw $KERNELCS, 8(%rsp)
  jz 1f

  /*
   * We came from user mode.  First switch to the kernel %GS register.
   */
  swapgs

  /*
   * Save the processor state in the per-processor user interrrupt context
   * structure.
   */
  call SVAsyscall

  /*
   * Call the trap handler registered by the OS for this trap.
   */
  movq $0, %rdi
  call *(interrupt_table+(8*0))

  /*
   * Restore the processor state.
   */
  call SVAsysret

  /*
   * Increment the PC by 2 to move past the idiv instruction.
   */
  addq $2, 0(%rsp)

  /*
   * Restore the user-space %GS register and return to user-space.
   */
  swapgs
  iretq

1:
  /*
   * We are in kernel mode.  Save the state on the kernel stack instead of
   * in the SVA virtual memory.
   */

  /* Push an error code on to the stack */
  pushq $0

  /* Save the %rbp register since we'll need to use it */
  pushq %rbp

  /* Allocate an interrupt context on the stack and fill it in */
  subq $176, %rsp

  /* Save the registers into the interrupt context */
  movq %rsp, %rbp
  call saveRegs

  /*
   * Get the current interrupt context link from the per-CPU data structure
   * and put it into our new interrupt context and put our new interrupt
   * context at the head of the list.
   */
  movq %rsp, %rdi
  call linkNewIC

  /*
   * Call the trap handler registered by the OS for this trap.
   */
  movq $0, %rdi
  call *(interrupt_table+(8*0))

  /*
   * Unlink the interrupt context.
   */
  movq %rsp, %rdi
  call unlinkIC

  /*
   * Copy the registers from the interrupt context back on to the processor.
   */
  call restoreRegs

  /* Remove the interrupt context and the error code */
  addq $176, %rsp
  popq %rbp
  addq $8, %rsp
  iretq

/*
 * Trap: SVAsyscall
 *
 * Description:
 *  This trap handles system call entry.
 *
 * Notes:
 *  The GS register should be pointing to the base of the interrupt context
 *  for the current processor.
 */
SVAsyscall:
  /*
   * Get a pointer to the current processor's interrupt context.
   */
  pushq %rbp
  movq %gs:0x260, %rbp

  /*
   * Set the next link to NULL (the user-space interrupt context should always
   * be the first in the interrupt context chain).
   */
  movq $0, 0x00(%rbp)

  /*
   * Save a copy of the interrupt context into SVA memory.
   */
  call saveRegs

  /*
   * Save a copy of the %rbp register into the interrupt context.
   */
  popq 0x88(%rbp)
  movq 0x88(%rbp), %rbp
  ret

SVAsysret:
  /*
   * Get a pointer to the current processor's interrupt context.
   */
  movq %gs:0x260, %rbp

  /*
   * Copy the registers from the interrupt context back on to the processor.
   */
  call restoreRegs

  /* Restore %rbp last */
  movq 0x88(%rbp), %rbp
  ret

  /* Exit the system call */
  sysretq

/*
 * Trap: secmemtrap
 *
 * Description:
 *  This trap handles secure memory allocations.
 *
 * Inputs:
 *  %rdi - This register should hold the size, in bytes, of secure memory to
 *         allocate.
 *
 * Return value:
 *  %rax - This register should hold a pointer to the allocated memory.
 */
secmemtrap:
  /* Use the swapgs instruction to switch to the kernel map */
  swapgs

  /* Call the secure memory allocator function */
  call  allocSecureMemory

  /* Use the swapgs instruction to switch back to user mode */
  swapgs

  /* Return from the trap */
  iretq

/*
 * Trap: secfreetrap
 *
 * Description:
 *  This trap handles secure memory deallocations.
 *
 * Inputs:
 *  %rdi - The pointer to the first byte of secure memory to deallocate.
 *  %rsi - This register should hold the size, in bytes, of secure memory to
 *         allocate.
 */
secfreetrap:
  /* Use the swapgs instruction to switch to the kernel map */
  swapgs

  /* Call the secure memory deallocator function */
  call  freeSecureMemory

  /* Use the swapgs instruction to switch back to user mode */
  swapgs

  /* Return from the trap */
  iretq


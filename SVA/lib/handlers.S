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
  movq %rsp, %rdi
  call SVAsyscall

  /*
   * Call the trap handler registered by the OS for this trap.
   */
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
  push $0

  /* Allocate an interrupt context on the stack and fill it in */
  subq $160, %rsp

  /* Save the registers into the interrupt context */
  movq %rdi,  8(%rsp)
  movq %rsi, 16(%rsp)

  movq %rax, 24(%rsp)
  movq %rbx, 32(%rsp)
  movq %rcx, 40(%rsp)
  movq %rdx, 48(%rsp)

  movq %r8,  56(%rsp)
  movq %r9,  64(%rsp)
  movq %r10, 72(%rsp)
  movq %r11, 80(%rsp)
  movq %r12, 88(%rsp)
  movq %r13, 96(%rsp)
  movq %r14, 104(%rsp)
  movq %r15, 112(%rsp)

  movq %rbp, 120(%rsp)

  movw %fs,  128(%rsp)
  movw %gs,  130(%rsp)
  movw %es,  132(%rsp)

  /*
   * Call the trap handler registered by the OS for this trap.
   */
  call *(interrupt_table+(8*0))

  /*
   * Copy the registers from the interrupt context back on to the processor.
   */
  movq   8(%rsp), %rdi
  movq  16(%rsp), %rsi

  movq  24(%rsp), %rax
  movq  32(%rsp), %rbx
  movq  40(%rsp), %rcx
  movq  48(%rsp), %rdx

  movq  56(%rsp), %r8
  movq  64(%rsp), %r9
  movq  72(%rsp), %r10
  movq  80(%rsp), %r11
  movq  88(%rsp), %r12
  movq  96(%rsp), %r13
  movq 104(%rsp), %r14
  movq 112(%rsp), %r15

  movq 120(%rsp), %rbp

#if 0
  movw 128(%rsp), %fs
  movw 130(%rsp), %gs
  movw 132(%rsp), %es
#endif

  /* Remove the interrupt context and the error code */
  addq $168, %rsp
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
  pushq %rax
  movq %gs:0x260, %rax

  /*
   * Save a copy of the interrupt context into SVA memory.
   */
  movq %rdi,  8(%rax)
  movq %rsi, 16(%rax)

  popq 24(%rax)
  movq %rbx, 32(%rax)
  movq %rcx, 40(%rax)
  movq %rdx, 48(%rax)

  movq %r8,  56(%rax)
  movq %r9,  64(%rax)
  movq %r10, 72(%rax)
  movq %r11, 80(%rax)
  movq %r12, 88(%rax)
  movq %r13, 96(%rax)
  movq %r14, 104(%rax)
  movq %r15, 112(%rax)

  movq %rbp, 120(%rax)

  movw %fs,  128(%rax)
  movw %gs,  130(%rax)
  movw %es,  132(%rax)

  /*
   * Restore the rax register.
   */
  movq 24(%rax), %rax
  ret

SVAsysret:
  /*
   * Get a pointer to the current processor's interrupt context.
   */
  movq %gs:0x260, %rax

  /*
   * Copy the registers from the interrupt context back on to the processor.
   */
  movq   8(%rax), %rdi
  movq  16(%rax), %rsi

  movq  32(%rax), %rbx
  movq  40(%rax), %rcx
  movq  48(%rax), %rdx

  movq  56(%rax), %r8
  movq  64(%rax), %r9
  movq  72(%rax), %r10
  movq  80(%rax), %r11
  movq  88(%rax), %r12
  movq  96(%rax), %r13
  movq 104(%rax), %r14
  movq 112(%rax), %r15

  movq 120(%rax), %rbp

#if 0
  movw 128(%rax), %fs
  movw 130(%rax), %gs
  movw 132(%rax), %es
#endif

  /* Restore %rax last */
  movq 24(%rax), %rax
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


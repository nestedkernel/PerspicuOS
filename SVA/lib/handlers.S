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

.global SVAsyscall
.type SVAsyscall, @function

.global SVAsysret
.type SVAsysret, @function

.global secmemtrap
.type secmemtrap, @function

.global secfreetrap
.type secfreetrap, @function

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
   * Save a copy of the interrupt context on to the stack
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

  /*
   * Restore the rax register.
   */
  movq 24(%rax), %rax
  ret

SVAsysret:
  /*
   * Get a pointer to the current processor's interrupt context.
   */
  pushq %rax
  movq %gs:0x260, %rax

  /*
   * Copy the registers from the interrupt context back on to the processor.
   */
  movq   8(%rax), %rdi
  movq  16(%rax), %rsi

  /* Don't restore %rax or %rdx; they are used for syscall return values */
  movq  32(%rax), %rbx
  movq  40(%rax), %rcx

  movq  56(%rax), %r8
  movq  64(%rax), %r9
  movq  72(%rax), %r10
#if 0
  movq  80(%rax), %r11
#endif
  movq  88(%rax), %r12
  movq  96(%rax), %r13
  movq 104(%rax), %r14
  movq 112(%rax), %r15

  movq 120(%rax), %rbp

  /* Get the return value from the original system call */
  popq %rax
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


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

.global secmemtrap
.type secmemtrap, @function

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


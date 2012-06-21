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
 */
secmemtrap:
  /* Use the swapgs instruction to switch to the kernel map */
  swapgs

  /* Return from the trap */
  call  sva_debug

  /* Use the swapgs instruction to switch back to user mode */
  swapgs
  iretq


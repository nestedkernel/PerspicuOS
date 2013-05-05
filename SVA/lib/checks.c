/*===- checks.c - SVA Execution Engine  =-----------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file implements run-time checks that the instrumentation pass does not
 * inline directly.
 *
 *===----------------------------------------------------------------------===
 */

#include "sva/mmu.h"

#include <sys/types.h>

void
sva_check_buffer (uintptr_t start, uintptr_t len) {
  /*
   * Compute the last address of the buffer.
   */
  uintptr_t end = start + len;

  /*
   * Treat the beginning of the ghost memory as address zero.  We have
   * overlap if either the first or last byte of the buffer, when normalized
   * to ghost memory, falls within the range of ghost memory.
   */
  uintptr_t secmemlen = (SECMEMEND - SECMEMSTART);
  uintptr_t nstart = start - SECMEMSTART;
  uintptr_t nend   = end   - SECMEMSTART;
  if ((nstart <= secmemlen) || (nend <= secmemlen)) {
    panic ("SVA: Invalid buffer access: %lx %lx\n", start, end);
  }
  return;
}


/*===- secmem.h - SVA Execution Engine  =------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file implements the new secure memory feature of SVA.
 *
 *===----------------------------------------------------------------------===
 */

#include <string.h>

#include <sys/types.h>

#include "sva/mmu.h"

/* Kernel callback function for allocating memory */
extern void * provideSVAMemory (uintptr_t size);
extern void releaseSVAMemory (void * p, uintptr_t size);

/*
 * Function: allocSecureMemory()
 *
 * Description:
 *  Allocate secure memory.  Fetch it from the operating system kernel if
 *  necessary.
 *
 * Inputs:
 *  size - The amount of secure memory to allocate measured in bytes.
 *
 * Return value:
 *  A pointer to the first byte of the secure memory.
 */
unsigned char *
allocSecureMemory (uintptr_t size) {
  /* Secure memory pointer */
  unsigned char * sp;

  /*
   * Get the memory from the operating system.
   */
  if ((sp = provideSVAMemory (size)) == 0) {
    /*
     * Zero out the memory.
     */
    memset (sp, 0, size);

    /*
     * TODO:
     * Unmap the memory from the MMU.
     */
  }

  /*
   * Return the memory to the caller.
   */
  return sp;
}

/*
 * Function: freeSecureMemory()
 *
 * Description:
 *  Free a single page of secure memory.
 *
 * Inputs:
 *  p    - The first virtual address of the secure memory to free.
 *  size - The amount of secure memory to allocate measured in bytes.
 */
void
freeSecureMemory (unsigned char * p, uintptr_t size) {
  /*
   * Zero out the memory.
   */
  memset (p, 0, size);

  /*
   * Release the memory to the operating system.
   */
  releaseSVAMemory (p, size);
  return;
}

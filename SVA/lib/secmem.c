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

#include "sva/callbacks.h"
#include "sva/mmu.h"

extern int printf(const char *, ...);

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
 *
 * Notes:
 *  The FreeBSD memory map has a gap at 0x0000800000000000 - 0xffff7fffffffffff.
 */
unsigned char *
allocSecureMemory (uintptr_t size) {
  /* Virtual address of allocated secure memory pointer */
  unsigned char * sp;

  /* Virtual address assigned to secure memory by SVA */
  unsigned char * vaddr = 0;

  /* Start of virtual address space used for secure memory */
  /* Note that using the memory gap doesn't seem to work, but this does */
#if 1
  static unsigned char * secmemp = (unsigned char *) 0x0000000000f00000u;
#else
  static unsigned char * secmemp = (unsigned char *) 0x00000000f0000000u;
#endif

  /*
   * Get the memory from the operating system.  Note that the OS provides a
   * virtual address of the allocated memory.
   */
  if ((sp = provideSVAMemory (size)) != 0) {
    /*
     * Assign the memory to live within the secure memory virtual address
     * space.
     */
    vaddr = secmemp;

    /*
     * Map each page of the memory into the part of the virtual address space
     * used for private memory.
     */
    for (unsigned char * p = sp; p < (sp + size); p += PAGE_SIZE) {
      /* Physical address of allocated secure memory */
      uintptr_t paddr;

      /*
       * Get the physical address of the memory page.
       */
      paddr = getPhysicalAddr (p);

      /*
       * Map the memory into a part of the address space reserved for secure
       * memory.
       */
      mapSecurePage (secmemp, paddr);

      /*
       * Let the next page use a different secure memory address.
       */
      secmemp += PAGE_SIZE;
    }

    /*
     * Zero out the memory.
     */
    memset (vaddr, 0, size);
  }

  /*
   * Return the memory to the caller.
   */
  return vaddr;
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
  printf ("SVA: freeSecureMemory: %p %lx\n", p, size);

  /*
   * Verify that the memory is within the secure memory portion of the
   * address space.
   *
   * TODO: Implement me!
   */

  /*
   * Zero out the memory.
   */
  memset (p, 0, size);

  /*
   * Unmap the memory from the secure memory virtual address space.
   */
  unmapSecurePage (p);

  /*
   * Release the memory to the operating system.
   */
#if 0
  releaseSVAMemory (p, size);
#endif
  return;
}

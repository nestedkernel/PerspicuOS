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

/* Start and end addresses of the secure memory */
#define SECMEMSTART 0xffffff0000000000u
#define SECMEMEND   0xffffff8000000000u

/*
 * Function: getNextSecureAddress()
 *
 * Description:
 *  Find the next available address in the secure virtual address space.
 *
 * Notes:
 *  This function is called by multiple processors, so it must be SMP-safe.
 */
unsigned char *
getNextSecureAddress (void) {
  /* Start of virtual address space used for secure memory */
  static unsigned char * secmemp = (unsigned char *) SECMEMSTART;

  /*
   * Advance the address by a single page frame and return the value before
   * increment.
   */
  return (unsigned char *)(__sync_fetch_and_add (((uintptr_t *)(&secmemp)), X86_PAGE_SIZE));
}

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
  /* Physical address of allocated secure memory pointer */
  uintptr_t sp;

  /* Virtual address assigned to secure memory by SVA */
  unsigned char * vaddr = 0;

  /*
   * Get the memory from the operating system.  Note that the OS provides the
   * physical address of the allocated memory.
   */
  if ((sp = provideSVAMemory (size)) != 0) {
    /*
     * Map each page of the memory into the part of the virtual address space
     * used for private memory.
     */
    for (uintptr_t paddr = sp; paddr < (sp + size); paddr += X86_PAGE_SIZE) {
      /*
       * Assign the memory to live within the secure memory virtual address
       * space.
       */
      vaddr = getNextSecureAddress();

      /*
       * Map the memory into a part of the address space reserved for secure
       * memory.
       */
      mapSecurePage (vaddr, paddr);
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
   */
  uintptr_t pint = (uintptr_t) p;
  if (SECMEMSTART <= pint < SECMEMEND) {
    /*
     * Zero out the memory.
     */
    memset (p, 0, size);

    /*
     * Get the physical address before unmapping the page.  We do this because
     * unmapping the page may remove page table pages that are no longer
     * needed for mapping secure pages.
     */
    uintptr_t paddr = getPhysicalAddr (p);

    /*
     * Unmap the memory from the secure memory virtual address space.
     */
    unmapSecurePage (p);

    /*
     * Release the memory to the operating system.  Note that we must first
     * get the physical address of the data page as that is what the OS is
     * expecting.
     */
    releaseSVAMemory (paddr, size);
  }

  return;
}

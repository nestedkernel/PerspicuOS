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
#include "sva/state.h"

/*
 * Function: getNextSecureAddress()
 *
 * Description:
 *  Find the next available address in the secure virtual address space.
 */
static inline unsigned char *
getNextSecureAddress (struct SVAThread * threadp) {
  /* Start of virtual address space used for secure memory */
  unsigned char * secmemStartp = (unsigned char *) SECMEMSTART;

  /* Secure memory address to return */
  unsigned char * secmemp = secmemStartp + threadp->secmemSize;

  /*
   * Advance the address by a single page frame and return the value before
   * increment.
   */
  threadp->secmemSize += X86_PAGE_SIZE;
  return secmemp;
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
allocSecureMemory (void) {
  /* Physical address of allocated secure memory pointer */
  uintptr_t sp;

  /* Virtual address assigned to secure memory by SVA */
  unsigned char * vaddrStart = 0;

  /* The address of the PML4e page table */
  pml4e_t pml4e = 0;

  /*
   * Get the current interrupt context; the arguments will be in it.
   */
  struct CPUState * cpup = getCPUState();
  struct SVAThread * threadp = cpup->currentThread;
  sva_icontext_t * icp = cpup->newCurrentIC;

  /*
   * Get the size out of the interrupt context.
   */
  uintptr_t size = icp->rdi;

  /*
   * Determine if this is the first secure memory allocation.
   */
  unsigned char firstSecAlloc = (threadp->secmemSize == 0);

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
      /* Virtual address for the current page to map */
      unsigned char * vaddr = 0;

      /*
       * Assign the memory to live within the secure memory virtual address
       * space.
       */
      vaddr = getNextSecureAddress(threadp);

      /*
       * If this is the virtual address of the first page, record it so that we
       * can return it to the caller.
       */
      if (!vaddrStart)
        vaddrStart = vaddr;

      /*
       * Map the memory into a part of the address space reserved for secure
       * memory.
       */
      pml4e = mapSecurePage (vaddr, paddr);

      /*
       * If this is the first piece of secure memory that we've allocated,
       * record the address of the top-level page table that maps in the secure
       * memory region.  The context switching intrinsics will want to know
       * where this entry is so that it can quickly enable and disable it on
       * context switches.
       */
      if (firstSecAlloc) {
        threadp->secmemPML4e = pml4e;
      }

      /*
       * Increase the size of the allocated secure memory.
       */
      threadp->secmemSize += size;
    }

    /*
     * Zero out the memory.
     */
    memset (vaddrStart, 0, size);
  }

  /*
   * Set the return value in the Interrupt Context to be a pointer to the newly
   * allocated memory.
   */
  icp->rax = (uintptr_t) vaddrStart;
  return vaddrStart;
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
 *
 * TODO:
 *  o) Size should be validated to prevent a fault in supervisor mode.
 */
void
freeSecureMemory (void) {
  /*
   * Get the current interrupt context; the arguments will be in it.
   */
  sva_icontext_t * icp = getCPUState()->newCurrentIC;

  /*
   * Get the pointer address and size out of the interrupt context.
   */
  unsigned char * p = (unsigned char *)(icp->rdi);
  uintptr_t size = icp->rsi;

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

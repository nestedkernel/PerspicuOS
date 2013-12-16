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
#include "sva/util.h"

/*
 * Function: getNextSecureAddress()
 *
 * Description:
 *  Find the next available address in the secure virtual address space.
 *
 * Inputs:
 *  threadp - The thread for which to allocate more ghost memory.
 *  size    - The size of memory to allocate in bytes.
 */
static inline unsigned char *
getNextSecureAddress (struct SVAThread * threadp, uintptr_t size) {
  /* Start of virtual address space used for secure memory */
  unsigned char * secmemStartp = (unsigned char *) SECMEMSTART;

  /* Secure memory address to return */
  unsigned char * secmemp = secmemStartp + threadp->secmemSize;

  /*
   * Advance the address by a single page frame and return the value before
   * increment.
   */
  threadp->secmemSize += size;
  return secmemp;
}

/*
 * Function: ghostMalloc()
 *
 * Description:
 *  Allocate ghost memory.
 */
unsigned char *
ghostMalloc (intptr_t size) {
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

  /*
   * Determine if this is the first secure memory allocation.
   */
  unsigned char firstSecAlloc = (threadp->secmemSize == 0);

  /*
   * Determine where this ghost memory will be allocated and update the size
   * of the ghost memory.
   */
  unsigned char * vaddr = vaddrStart = getNextSecureAddress (threadp, size);

  /*
   * Get a page of memory from the operating system.  Note that the OS provides
   * the physical address of the allocated memory.
   */
  for (intptr_t remaining = size; remaining > 0; remaining -= X86_PAGE_SIZE) {
    if ((sp = provideSVAMemory (X86_PAGE_SIZE)) != 0) {
      /* Physical address of the allocated page */
      uintptr_t paddr = sp;

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
       * Move to the next virtual address.
       */
      vaddr += X86_PAGE_SIZE;
    } else {
      panic ("SVA: Kernel secure memory allocation failed!\n");
    }
  }

  /* Return a pointer to the allocated ghost memory */
  return vaddrStart;
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
  /*
   * Get the number of bytes to allocate.  This is stored in the %rdi register
   * of the interrupted program state.
   */
  struct CPUState * cpup = getCPUState();
  sva_icontext_t * icp = cpup->newCurrentIC;
  intptr_t size = icp->rdi;

  /*
   * Check that the size is positive.
   */
  if (size < 0)
    return 0;

  /*
   * If we have already allocated ghost memory, then merely extend the size of
   * of the ghost partition and let the ghost memory be demand paged into
   * memory.  Otherwise, allocate some ghost memory just to make adding the
   * demand-paged ghost memory easier.
   */
  unsigned char * vaddrStart = 0;
  struct SVAThread * threadp = cpup->currentThread;
  if (threadp->secmemSize) {
    /*
     * Pretend to allocate more ghost memory (but let demand paging actually
     * map it in.
     */
    vaddrStart = getNextSecureAddress (threadp, size);
  } else {
    /*
     * Call the ghost memory allocator to allocate some ghost memory.
     */
    vaddrStart = ghostMalloc (size);

    /*
     * Zero out the memory.
     */
    memset (vaddrStart, 0, size);
  }

  /*
   * Set the return value in the Interrupt Context to be a pointer to the
   * newly allocated memory.
   */
  icp->rax = (uintptr_t) vaddrStart;

  /*
   * Return the first address of the newly available ghost memory.
   */
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
  if ((SECMEMSTART <= pint < SECMEMEND) &&
     (SECMEMSTART <= (pint + size) < SECMEMEND)) {
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
    unmapSecurePage (get_pagetable(), p);

    /*
     * Release the memory to the operating system.  Note that we must first
     * get the physical address of the data page as that is what the OS is
     * expecting.
     */
    releaseSVAMemory (paddr, size);
  }

  return;
}

void
sva_ghost_fault (uintptr_t vaddr) {
  /* Old interrupt flags */
  uintptr_t rflags;

  /*
   * Disable interrupts.
   */
  rflags = sva_enter_critical();

  /* Physical address of allocated secure memory pointer */
  uintptr_t sp;

  /* The address of the PML4e page table */
  pml4e_t pml4e;

  /*
   * Get the current interrupt context; the arguments will be in it.
   */
  struct CPUState * cpup = getCPUState();
  struct SVAThread * threadp = cpup->currentThread;

  /*
   * Determine if this is the first secure memory allocation.
   */
  unsigned char firstSecAlloc = (threadp->secmemSize == 0);

  /*
   * Get a page of memory from the operating system.  Note that the OS provides
   * the physical address of the allocated memory.
   */
  if ((sp = provideSVAMemory (X86_PAGE_SIZE)) != 0) {
    /* Physical address of the allocated page */
    uintptr_t paddr = (uintptr_t) sp;

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
  } else {
    panic ("SVA: Kernel secure memory allocation failed!\n");
  }

  /*
   * Zero out the ghost memory contents.
   */
  memset (vaddr, 0, X86_PAGE_SIZE);

  /* Re-enable interrupts if necessary */
  sva_exit_critical (rflags);
  return;
}


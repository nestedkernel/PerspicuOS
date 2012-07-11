/*===- kern_sva.c - SVA Kernel Callbacks =-----------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file implements functions that the kernel needs to provide to SVA.
 *
 *===----------------------------------------------------------------------===
 */

#include <sys/malloc.h>
#include <sys/types.h>

#include <sys/cdefs.h>
#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_reserv.h>
#include <vm/pmap.h>
#include <vm/uma.h>

/* Function prototypes */
void * provideSVAMemory (uintptr_t size);
void releaseSVAMemory (void * p, uintptr_t size);

/*
 * Function: provideSVAMemory()
 *
 * Description:
 *  Allocate memory and pass it to SVA to use.
 *
 * Inputs:
 *  The amount of memory to give SVA in bytes.
 *
 * Return value:
 *  The first virtual address of the memory that SVA can use.
 */
static char buffer[4096] __attribute__ ((aligned (4096)));

void *
provideSVAMemory (uintptr_t size)
{
  /* Structure to get a page */
  vm_page_t bufferPage;

  /* Virtual address of memory to be returned. */
  void * p;

  /*
   * Check to see if a single page will do.  If not, then panic.
   */
  if (size > 4096u)
    panic ("SVA: providesSVAMemory: Too much memory requested: %ld\n", size);

  /*
   * Request a page from the page manager.
   */
	bufferPage = vm_page_alloc (NULL, 0, VM_ALLOC_NORMAL);

  /*
   * Convert the page into a physical address.
   */
	p = (void *) PHYS_TO_DMAP(VM_PAGE_TO_PHYS(bufferPage));

  printf ("SVA: providesSVAMemory: %p -> %lx\n", p, vtophys (p));
	return p;
}

/*
 * Function: releaseSVAMemory()
 *
 * Description:
 *  SVA calls this function when it no longer needs a piece of memory.
 *
 * Inputs:
 *  p    - The first virtual address of the memory to release back to the OS.
 *  size - The length of the memory in bytes to release.
 *
 */
void
releaseSVAMemory (void * p, uintptr_t size)
{
  /* Paging structure for the memory */
  vm_page_t page;

  /*
   * Convert the virtual address into a physical address, and then convert the
   * physical address into a vm_page_t.
   */
  vm_paddr_t paddr = vtophys (p);
  page = vm_phys_paddr_to_vm_page (paddr);

  /*
   * Now free the page.
   */
  vm_page_free (page);
  return;
}

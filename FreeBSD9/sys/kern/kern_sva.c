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

#if 0
#include "opt_pmap.h"
#include "opt_vm.h"
#endif

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
    panic ("SVA: providesSVAMemory: Too much memory requested!\n");

  /*
   * Request a page from the page manager.
   */
	bufferPage = vm_page_alloc (NULL, 0, VM_ALLOC_NORMAL | VM_ALLOC_WIRED);

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
#if 0
	return free (p, M_KOBJ);
#endif
}

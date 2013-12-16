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
#include <sys/proc.h>

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

#include <sys/pcpu.h>
#include <machine/frame.h>

/* Function prototypes */
uintptr_t provideSVAMemory (uintptr_t size);
void releaseSVAMemory (uintptr_t p, uintptr_t size);

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
 *  The first physical address of the memory that SVA can use.
 */
uintptr_t
provideSVAMemory (uintptr_t size)
{
  /* Structure to get a page */
  vm_page_t bufferPage;

  /* Virtual address of memory to be returned. */
  unsigned char * p;

  /*
   * Check to see if a single page will do.  If not, then panic.
   */
  if (size > 4096u)
    panic ("SVA: providesSVAMemory: Too much memory requested: %ld\n", size);

  /*
   * Request a page from the page manager.
   */
	bufferPage = vm_page_alloc (NULL, 0, VM_ALLOC_NORMAL | VM_ALLOC_NOOBJ);

  /*
   * Unmap the page from the 1 TB direct map.
   */
	p = (void *) PHYS_TO_DMAP(VM_PAGE_TO_PHYS(bufferPage));
  pmap_remove (&(curproc->p_vmspace->vm_pmap),
               (vm_offset_t) p,
               (vm_offset_t) p + 4096);

  /*
   * Convert the page into a physical address and return it.
   */
	return VM_PAGE_TO_PHYS(bufferPage);
}

/*
 * Function: releaseSVAMemory()
 *
 * Description:
 *  SVA calls this function when it no longer needs a piece of memory.
 *
 * Inputs:
 *  paddr - The first physical address of the memory to release back to the OS.
 *  size  - The length of the memory in bytes to release.
 *
 */
void
releaseSVAMemory (uintptr_t paddr, uintptr_t size)
{
  /* Paging structure for the memory */
  vm_page_t page;

  /*
   * Convert the physical address into a vm_page_t.
   */
  page = vm_phys_paddr_to_vm_page (paddr);

  /*
   * Figure out where in the virtual address space it should go.
   */
	unsigned char * p = (void *) PHYS_TO_DMAP(VM_PAGE_TO_PHYS(page));

  /*
   * Remap the page back into the direct 1 TB map.
   */
  pmap_enter (&(curproc->p_vmspace->vm_pmap),
               (vm_offset_t) p,
               0,
               page,
               VM_PROT_READ | VM_PROT_WRITE,
               0);

  /*
   * Now free the page.
   */
  vm_page_free (page);
  return;
}

/*
 * Function: testSVAMemory()
 *
 * Description:
 *  Try to access secure memory.
 */
void
testSVAMemory (unsigned char * p) {
  /*
   * Testing time: Attempt to access the secure memory.
   */
  printf ("Kernel: Spying on you!  Secret is: \n");
  for (int index = 0; index < 5; ++index) {
    printf ("%c", p[index]);
  }
  printf ("\n");
  return;
}


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
void *
provideSVAMemory (uintptr_t size)
{
	return malloc (size);
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
	return free (p);
}

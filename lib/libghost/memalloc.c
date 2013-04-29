/*===- memalloc.c - Ghost Compatibility Library ---------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file defines ghost allocation versions of malloc() and friends.
 *
 *===----------------------------------------------------------------------===
 */

#include <stdlib.h>

#include <sys/types.h>
#include <unistd.h>

/*
 * Function: secmemalloc()
 *
 * Description:
 *  Ask the SVA VM to allocate some ghost memory.
 */
static inline void *
secmemalloc (uintptr_t size) {
  void * ptr;
  __asm__ __volatile__ ("movq %1, %%rdi\n"
                        "int $0x7f\n" : "=a" (ptr) : "r" (size));
  return ptr;
}

#if 0
void *
ghost_malloc(size_t size) {
  printf ("ghost_malloc!\n");
  return secmemalloc (size);
}

void *
ghost_calloc(size_t number, size_t size) {
  printf ("ghost_calloc!\n");
  void * ptr = secmemalloc (number * size);
  memset (ptr, 0, number * size);
  return ptr;
}

void *
ghost_realloc(void *ptr, size_t size) {
  realloc (ptr, size);
}

void *
ghost_reallocf(void *ptr, size_t size) {
  reallocf (ptr, size);
}
#endif

void *
ghost_sbrk (intptr_t incr) {
  static uintptr_t totalAllocated = 0;
  static uintptr_t currentSize = 0;
  static uintptr_t start = 0xffffff0000000000u;
  void * oldBrk = (void *)(start + currentSize);

  if (getenv ("GHOSTING") == NULL)
    return sbrk (incr);

  // Caller is asking to increase the allocation space
  if (incr > 0) {
    //
    // If we have enough space remaining, simply increase the current size.
    // Otherwise, go allocate more secure memory.
    //
    if ((totalAllocated - currentSize) >= incr) {
      currentSize += incr;
    } else {
      secmemalloc (incr - (totalAllocated - currentSize));
      currentSize += incr;
    }
  }

  // Caller is asking to decrease the allocation space
  if (incr < 0) {
    currentSize += incr;
  }

  //
  // Return the previous break value: note that an input increment of zero
  // returns the current (unchanged) break value.
  //
  return oldBrk;
}

//////////////////////////////////////////////////////////////////////////////
// Define weak aliases to make the wrappers appear as the actual library call
//////////////////////////////////////////////////////////////////////////////

#if 0
void * malloc () __attribute__ ((weak, alias ("ghost_malloc")));
void * calloc () __attribute__ ((weak, alias ("ghost_calloc")));
void * realloc () __attribute__ ((weak, alias ("ghost_realloc")));
void * reallocf () __attribute__ ((weak, alias ("ghost_reallocf")));
#endif
void * sbrk () __attribute__ ((weak, alias ("ghost_sbrk")));

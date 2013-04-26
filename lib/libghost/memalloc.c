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

void *
ghost_malloc(size_t size) {
  printf ("ghost_malloc!\n");
  return secmemalloc (size);
}

void *
ghost_calloc(size_t number, size_t size) {
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

//////////////////////////////////////////////////////////////////////////////
// Define weak aliases to make the wrappers appear as the actual library call
//////////////////////////////////////////////////////////////////////////////

void * malloc () __attribute__ ((weak, alias ("ghost_malloc")));
void * calloc () __attribute__ ((weak, alias ("ghost_calloc")));
void * realloc () __attribute__ ((weak, alias ("ghost_realloc")));
void * reallocf () __attribute__ ((weak, alias ("ghost_reallocf")));

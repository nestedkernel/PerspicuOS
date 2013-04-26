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

#include "ghost.h"

void *
ghost_malloc(size_t size) {
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

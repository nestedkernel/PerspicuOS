/*===- ghost.c - Ghost Compatibility Library ------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file defines compatibility functions to permit ghost applications to
 * use system calls.
 *
 *===----------------------------------------------------------------------===
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <cstdio>
#include <cstdlib>

#include "ghost.h"

/* Size of traditional memory buffer */
static uintptr_t tradlen = 4096;

/* Buffer containing the traditional memory */
static unsigned char * tradBuffer;

/* Pointer into the traditional memory buffer stack */
static unsigned char * tradsp;

//
// Function: ghostinit()
//
// Description:
//  This function initializes the ghost run-time.  It should be called in a
//  program's main() function.
//
void
ghostinit (void) {
  tradBuffer = (unsigned char *) mmap(0, tradlen, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
  if (tradBuffer == MAP_FAILED) {
    abort ();
  }

  tradsp = tradBuffer;
  return;
}

//
// Template: allocateTradMem()
//
// Description:
//  Allocate traditional memory.
//
template<typename T>
static inline T *
allocate (unsigned char * & framePointer, T * data) {
  //
  // Save the current location of the traditional memory stack pointer.
  //
  framePointer = tradsp;

  //
  // Allocate memory on the traditional memory stack.
  //
  tradsp += sizeof (T);

  //
  // Copy the data into the traditional memory.
  //
  T * copy = (T *)(tradsp);
  return copy;
}

//
// Template: allocateTradMem()
//
// Description:
//  Allocate traditional memory and copy the contents of a memory object into
//  it.  This is useful for setting up input data.
//
template<typename T>
static inline T *
allocAndCopy (unsigned char * & framePointer, T* data) {
  //
  // Save the current location of the traditional memory stack pointer.
  //
  framePointer = tradsp;

  //
  // Allocate memory on the traditional memory stack.
  //
  tradsp += sizeof (T);

  //
  // Copy the data into the traditional memory.
  //
  T * copy = (T *)(tradsp);
  *copy = *data;
  return copy;
}

//////////////////////////////////////////////////////////////////////////////
// Wrappers for system calls
//////////////////////////////////////////////////////////////////////////////

int
_accept (int s, struct sockaddr * addr, socklen_t * addrlen) {
  unsigned char * framep;
  struct sockaddr * newaddr = allocAndCopy (framep, addr);
  socklen_t * newlen = allocAndCopy (framep, addrlen);
  accept (s, newaddr, newlen);
  return 0;
}

int
_fstat(int fd, struct stat *sb) {
  int ret;
  unsigned char * framep;
  struct stat * newsb = allocate (framep, sb);
  printf ("Calling fstat\n");
  ret = fstat (fd, newsb);
  *sb = *newsb;
  return ret;
}

//////////////////////////////////////////////////////////////////////////////
// Define weak aliases to make the wrappers appear as the actual system call
//////////////////////////////////////////////////////////////////////////////

void accept () __attribute__ ((weak, alias ("_accept")));
void fstat () __attribute__ ((weak, alias ("_fstat")));

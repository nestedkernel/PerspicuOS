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

#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

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
allocate (T * data) {
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
allocAndCopy (T* data) {
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

static inline char *
allocAndCopy (char * data) {
  //
  // Allocate memory on the traditional memory stack.
  //
  tradsp += (strlen (data) + 1);

  //
  // Copy the data into the traditional memory.
  //
  char * copy = (char *)(tradsp);
  strcpy (copy, data);
  return copy;
}

//////////////////////////////////////////////////////////////////////////////
// Wrappers for system calls
//////////////////////////////////////////////////////////////////////////////

#if 0
int
_accept (int s, struct sockaddr * addr, socklen_t * addrlen) {
  int ret;
  unsigned char * framep;
  struct sockaddr_un * newaddr = allocate (framep, addr);
  socklen_t * newlen = allocate (framep, addrlen);
  ret = accept (s, newaddr, newlen);

  // Copy the outputs back into secure memory
  memcpy (addr, newaddr, *newlen);
  memcpy (addrlen, newlen, sizeof (socklen_t));

  // Restore the stack pointer
  tradsp = framep;
  return ret;
}
#endif

int
_open (char *path, int flags, mode_t mode) {
  // Save the current location of the traditional memory stack pointer.
  unsigned char * framep = tradsp;

  char * newpath = allocAndCopy (path);
  int fd = open (newpath, flags, mode);

  // Restore the stack pointer
  tradsp = framep;
  return fd;
}

#if 0
ssize_t
_readlink(const char * path, char * buf, size_t bufsiz) {
  ssize_t size;
  unsigned char * framep;
  char * newpath = allocAndCopy (path);

  // Perform the system call
  size = readlink (newpath, newbuf, bufsiz);

  // Restore the stack pointer
  tradsp = framep;
  return size;
}
#endif

int
_fstat(int fd, struct stat *sb) {
  // Save the current location of the traditional memory stack pointer.
  unsigned char * framep = tradsp;

  struct stat * newsb = allocate (sb);
  int ret = fstat (fd, newsb);

  // Copy the outputs back into secure memory
  *sb = *newsb;

  // Restore the stack pointer
  tradsp = framep;
  return ret;
}

//////////////////////////////////////////////////////////////////////////////
// Define weak aliases to make the wrappers appear as the actual system call
//////////////////////////////////////////////////////////////////////////////

void accept () __attribute__ ((weak, alias ("_accept")));
void fstat () __attribute__ ((weak, alias ("_fstat")));
void open () __attribute__ ((weak, alias ("_open")));

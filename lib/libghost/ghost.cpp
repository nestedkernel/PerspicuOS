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
#include <sys/select.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "ghost.h"

/* Size of traditional memory buffer */
static uintptr_t tradlen = 16384;

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

  tradsp = tradBuffer + tradlen;
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
  tradsp -= sizeof (T);

  //
  // Copy the data into the traditional memory.
  //
  T * copy = (T *)(tradsp);
  return copy;
}

static inline
char * allocate (uintptr_t size) {
  //
  // Allocate memory on the traditional memory stack.
  //
  tradsp -= size;

  //
  // Copy the data into the traditional memory.
  //
  char * copy = (char *)(tradsp);
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
  T * copy = 0;
  if (data) {
    //
    // Allocate memory on the traditional memory stack.
    //
    tradsp -= sizeof (T);

    //
    // Copy the data into the traditional memory.
    //
    copy = (T *)(tradsp);
    *copy = *data;
  }
  return copy;
}

static inline fd_set *
allocAndCopy (fd_set* data) {
  fd_set * copy = 0;
  if (data) {
    //
    // Allocate memory on the traditional memory stack.
    //
    tradsp -= sizeof (fd_set);

    //
    // Copy the data into the traditional memory.
    //
    fd_set * copy = (fd_set *)(tradsp);
    *copy = *data;
  }
  return copy;
}

static inline char *
allocAndCopy (char * data) {
  //
  // Allocate memory on the traditional memory stack.
  //
  tradsp -= (strlen (data) + 1);

  //
  // Copy the data into the traditional memory.
  //
  char * copy = (char *)(tradsp);
  if (data)
    strcpy (copy, data);
  return copy;
}

static inline char *
allocAndCopy (void * data, uintptr_t size) {
  //
  // Allocate memory on the traditional memory stack.
  //
  tradsp -= (size);

  //
  // Copy the data into the traditional memory.
  //
  char * copy = (char *)(tradsp);
  if (data)
    memcpy (copy, data, size);
  return copy;
}


//////////////////////////////////////////////////////////////////////////////
// Wrappers for system calls
//////////////////////////////////////////////////////////////////////////////

int
_accept (int s, struct sockaddr * addr, socklen_t * addrlen) {
  int ret;
  unsigned char * framep = tradsp;
  if (addr && addrlen) {
    struct sockaddr * newaddr = (struct sockaddr *) allocate (*addrlen);
    socklen_t * newaddrlen = allocAndCopy (addrlen);

    // Perform the system call
    ret = accept (s, newaddr, newaddrlen);

    // Copy the outputs back into secure memory
    memcpy (addr, newaddr, *newaddrlen);
    memcpy (addrlen, newaddrlen, sizeof (socklen_t));

    // Restore the stack pointer
    tradsp = framep;
  } else {
    ret = accept (s, addr, addrlen);
  }
  return ret;
}

int
_bind(int s, const struct sockaddr *addr, socklen_t addrlen) {
  int ret;
  unsigned char * framep = tradsp;
  struct sockaddr * newaddr = (struct sockaddr *) allocate (addrlen);
  memcpy (newaddr, addr, addrlen);

  // Perform the system call
  ret = bind (s, newaddr, addrlen);

  // Restore the stack pointer
  tradsp = framep;
  return ret;
}

int
_getsockopt(int s, int level, int optname, void * optval, socklen_t * optlen) {
  int ret;
  unsigned char * framep = tradsp;
  void * newoptval = allocate (*optlen);
  socklen_t * newoptlen = allocAndCopy (optlen);

  // Perform the system call
  ret = getsockopt (s, level, optname, newoptval, newoptlen);

  // Copy the outputs back into secure memory
  memcpy (optval, newoptval, *newoptlen);
  memcpy (optlen, newoptlen, sizeof (socklen_t));

  // Restore the stack pointer
  tradsp = framep;
  return ret;
}

int
ghost_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
        struct timeval *timeout) {
  // Save the current location of the traditional memory stack pointer.
  unsigned char * framep = tradsp;

  fd_set * newreadfds = allocAndCopy (readfds);
  fd_set * newwritefds = allocAndCopy (writefds);
  fd_set * newexceptfds = allocAndCopy (exceptfds);
  struct timeval * newtimeout = allocAndCopy (timeout);

  // Perform the system call
  int err = select (nfds, newreadfds, newwritefds, newexceptfds, newtimeout);

  static char * output = "select done!\n";
  write (1, output, strlen (output));

  // Copy the outputs back into ghost memory
  if (readfds)   *readfds   = *newreadfds;
  if (writefds)  *writefds  = *newwritefds;
  if (exceptfds) *exceptfds = *newexceptfds;

  // Restore the stack pointer
  tradsp = framep;
  return err;
}

int
_pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
        struct timespec *timeout, sigset_t * sigmask) {
  // Save the current location of the traditional memory stack pointer.
  unsigned char * framep = tradsp;

  fd_set * newreadfds = allocAndCopy (readfds);
  fd_set * newwritefds = allocAndCopy (writefds);
  fd_set * newexceptfds = allocAndCopy (exceptfds);
  struct timespec * newtimeout = allocAndCopy (timeout);
  sigset_t * newsigmask = allocAndCopy (sigmask);

  // Perform the system call
  int err = pselect (nfds, newreadfds, newwritefds, newexceptfds, newtimeout, newsigmask);

  // Copy the outputs back into ghost memory
  if (readfds)   *readfds   = *newreadfds;
  if (writefds)  *writefds  = *newwritefds;
  if (exceptfds) *exceptfds = *newexceptfds;

  // Restore the stack pointer
  tradsp = framep;
  return err;
}

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

int
_mkdir(char *path, mode_t mode) {
  // Save the current location of the traditional memory stack pointer.
  unsigned char * framep = tradsp;

  char * newpath = allocAndCopy (path);

  // Perform the system call
  int err = mkdir (newpath, mode);

  // Restore the stack pointer
  tradsp = framep;
  return err;
}

ssize_t
_readlink(char * path, char * buf, size_t bufsiz) {
  ssize_t size;
  unsigned char * framep = tradsp;
  char * newpath = allocAndCopy (path);
  char * newbuf = allocate (bufsiz);

  // Perform the system call
  size = readlink (newpath, newbuf, bufsiz);

  // Restore the stack pointer
  tradsp = framep;
  return size;
}

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

int
stat(char *path, struct stat *sb) {
  // Save the current location of the traditional memory stack pointer.
  unsigned char * framep = tradsp;

  char * newpath = allocAndCopy (path);
  struct stat * newsb = allocate (sb);
  int ret = stat (newpath, newsb);

  // Copy the outputs back into secure memory
  *sb = *newsb;

  // Restore the stack pointer
  tradsp = framep;
  return ret;
}

ssize_t
_read(int d, void *buf, size_t nbytes) {
  ssize_t size;
  unsigned char * framep = tradsp;
  char * newbuf = allocate (nbytes);

  // Perform the system call
  size = read (d, newbuf, nbytes);

  // Copy the data back into the buffer
  memcpy (buf, newbuf, size);

  // Restore the stack pointer
  tradsp = framep;
  return size;
}

ssize_t
_write(int d, void *buf, size_t nbytes) {
  ssize_t size;
  unsigned char * framep = tradsp;
  char * newbuf = allocAndCopy (buf, nbytes);

  // Perform the system call
  size = write (d, newbuf, nbytes);

  // Restore the stack pointer
  tradsp = framep;
  return size;
}

int
_clock_gettime(clockid_t clock_id, struct timespec *tp) {
  int ret;
  unsigned char * framep = tradsp;
  struct timespec * newtp = allocate (tp);

  // Perform the system call
  ret = clock_gettime (clock_id, newtp);

  // Copy the data out
  *tp = *newtp;

  // Restore the stack pointer
  tradsp = framep;
  return ret;
}

//////////////////////////////////////////////////////////////////////////////
// Define weak aliases to make the wrappers appear as the actual system call
//////////////////////////////////////////////////////////////////////////////

void accept () __attribute__ ((weak, alias ("_accept")));
void bind () __attribute__ ((weak, alias ("_bind")));
void getsockopt () __attribute__ ((weak, alias ("_getsockopt")));

int select () __attribute__ ((weak, alias ("ghost_select")));
int pselect () __attribute__ ((weak, alias ("_pselect")));

void open () __attribute__ ((weak, alias ("_open")));
void readlink () __attribute__ ((weak, alias ("_readlink")));
void mkdir () __attribute__ ((weak, alias ("_mkdir")));
void stat () __attribute__ ((weak, alias ("_stat")));
void fstat () __attribute__ ((weak, alias ("_fstat")));
void read () __attribute__ ((weak, alias ("_read")));
void write () __attribute__ ((weak, alias ("_write")));
void clock_gettime () __attribute__ ((weak, alias ("_clock_gettime")));

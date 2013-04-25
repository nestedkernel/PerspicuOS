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

/* Size of traditional memory buffer */
static const uintptr_t tradlen = 4096;

/* Buffer containing the traditional memory */
static unsigned char * tradBuffer;

/* Pointer into the traditional memory buffer stack */
static unsigned char * tradsp;

ghostinit (void) {
  tradBuffer = mmap(0, tradlen, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
  if (tradBuffer == MAP_FAILED) {
    abort ();
  }

  tradsp = tradBuffer;
}

int
accept (int s, struct sockaddr * restrict addr, socklen_t * restrict addrlen) {
  struct args {
    struct sockaddr_un addr;
    socklen_t addrlen;
  };

  unsigned char * tradbp = tradsp;
  tradsp += sizeof (struct args);
}

int
accept2 (int s, struct sockaddr * restrict addr, socklen_t * restrict addrlen) {
  unsigned char * tradbp = tradsp;
  struct args {
    socklen_t addrlen;
    struct sockaddr_un addr;
  };
}

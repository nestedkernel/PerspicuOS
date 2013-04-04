#include <stdio.h>
#include <stdlib.h>

#include <signal.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>

int
main (int argc, char ** argv) {
  /* Pointer to memory */
  unsigned char * p1;
  unsigned char * p2;

  /*
   * Map two physical pages into memory.
   */
  p1 = mmap (0, 8192, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
  if (p1 == MAP_FAILED) {
    fprintf (stderr, "mmap failed: %d!\n", errno);
    return 1;
  }

  p2 = p1 + 4096;

  /*
   * Change the page protections on the second page.
   */
  if (mprotect (p2, 4096, PROT_NONE) == -1) {
    fprintf (stderr, "mprotect failed: %d!\n", errno);
    return 1;
  }

  /*
   * Attempt to read data into the invalid memory.
   */
  if (read (STDIN_FILENO, p1 + 4090, 4096) == -1) {
    if (errno == EFAULT)
      fprintf (stderr, "Got EFAULT!\n");
    else
      fprintf (stderr, "Got %d\n", errno);
    fflush (stderr);
  } else {
    fprintf (stderr, "Read Worked\n");
  }

  return 0;
}


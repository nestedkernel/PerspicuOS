#include <stdio.h>
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
  __asm__ __volatile__ ("int $0x7f\n" : "=a" (ptr) : "D" (size));
  return ptr;
}

int
main (int argc, char ** argv) {
  unsigned long index;
  unsigned char * ptr1 = 0;
  unsigned long numAllocs = 0;

  /*
   * Check that we have the correct number of arguments.
   */
  if (argc < 2) {
    printf ("Usage: %s <number of bytes to allocate?\n", argv[0]);
    return -1;
  }

  /*
   * Get the number of ghost memory allocations to perform.
   */
  numAllocs = strtoul (argv[1], NULL, 0);
  printf ("Number of allocations: %lx\n", numAllocs);
  fflush (stdout);

  /*
   * Call the secure memory allocator.
   */
  for (index = 0; index < numAllocs; ++index) {
#if 0
    ptr1 = (unsigned char *) secmemalloc (0x80100);
#else
    ptr1 = (unsigned char *) secmemalloc (0x10000);
#endif
    printf ("Secure Memory at %p\n", ptr1);
    fflush (stdout);
  }

  return 0;
}

#include <stdio.h>
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
  __asm__ __volatile__ ("int $0x7f\n" : "=a" (ptr) : "D" (size));
  return ptr;
}

int
main (int argc, char ** argv) {
  unsigned char * ptr1 = 0;
  unsigned char * ptr2 = 0;
  unsigned long size = 0;
  unsigned index;
  unsigned sum = 0;

  /*
   * Check that we have the correct number of arguments.
   */
  if (argc < 2) {
    printf ("Usage: %s <number of bytes to allocate?\n", argv[0]);
    return -1;
  }

  /*
   * Get the number of bytes of secure memory to allocate.
   */
  size = strtoul (argv[1], NULL, 0);
  printf ("Secure Memory size: %lx\n", size);
  fflush (stdout);

  /*
   * Call the secure memory allocator.
   */
  ptr1 = secmemalloc (size);
  ptr2 = secmemalloc (size);
  printf ("Secure Memory at %p %p\n", ptr1, ptr2);
  fflush (stdout);

  /*
   * Read and write ghost memory.
   */
  unsigned char counter = argv[0][0];
  while (1) {
    ptr1[0] = counter++;
    ptr2[0] = ptr1;
    printf ("%p %p %d\n", ptr1, ptr2, counter);
    fflush (stdout);
  }
  return 0;
}

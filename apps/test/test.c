#include <stdio.h>
#include <stdlib.h>

int
main (int argc, char ** argv) {
  unsigned char * ptr = 0;
  unsigned long size = 0;
  unsigned index;
  unsigned sum = 0;
  size = strtoul (argv[1], NULL, 0);
  __asm__ __volatile__ ("movq %1, %%rdi\nint $0x7f\n" : "=a" (ptr) : "r" (size));
  __asm__ __volatile__ ("movq %1, %%rdi\nint $0x7f\n" : "=a" (ptr) : "r" (size));
  printf ("Secure Memory at %p\n", (void *)ptr);

  printf ("Reading Secure Memory at %p\n", (void *)ptr);
  fflush (stdout);
  for (index = 0; index < size; ++index) {
    printf ("Address: %p\n", &(ptr[index]));
    fflush (stdout);
    sum += ptr[index];
  }
  printf ("%d\n", sum);

  return 0;
}

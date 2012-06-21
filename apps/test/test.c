#include <stdio.h>
#include <stdlib.h>

int
main () {
  void * ptr;
  __asm__ __volatile__ ("movq $8, %%rdi\nint $0x7f\n" : "=a" (ptr));
  printf ("%p\n", ptr);
  return 0;
}

#include <stdio.h>
#include <stdlib.h>

unsigned long rax = 0xbeef;
unsigned long rsp = 0xbeef;
unsigned long rbp = 0xbeef;
unsigned long newrbp = 0;

int
main (int argc, char ** argv) {

  __asm__ __volatile__ ("movq %%rax, %0\n"
                        "movq %%rbp, %1\n"
                        "movq %%rsp, %2\n"
                        : "=m" (rax), "=m" (rbp), "=m" (rsp));

  printf ("Before: rax = %lx, rbp = %lx, rsp=%lx\n", rax, rbp, rsp);
  fflush (stdout);

  __asm__ __volatile__ ("syscall\n"
                        "movq %%rbp, %0\n"
                        : "=m" (newrbp)
                        : "a" (0x8000003d));

  printf ("After : rax = %lx, rbp = %lx, rsp=%lx\n", rax, rbp, rsp);
  fflush (stdout);
}

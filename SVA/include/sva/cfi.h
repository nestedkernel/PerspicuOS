/*===- cfi.h - SVA Execution Engine  =-------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file defines macros that can be used to add CFI checks and labels to
 * hand-written assembly code.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef SVA_CFI_H
#define SVA_CFI_H

/* Labels for call targets and return targets, respectively */
#define CALLLABEL 0xbeefbeef
#define RETLABEL  0xbeefbeef

/* Labels used in comparisons: This includes the prefetchnta portion */
#define CHECKLABEL 0x80180F67

/* Macro for call */
#define CALLQ(x) callq x ; \
								 prefetchnta RETLABEL(%eax)

/* Macro for start of function */
#define STARTFUNC prefetchnta CALLLABEL(%eax)
#define RETTARGET prefetchnta RETLABEL(%eax)

/* Macro for return */
#define RETQ  movq  (%rsp), %rcx ; \
              movl  $0xffffff80, %edx ; \
              shlq   $32, %rdx ; \
              orq   %rdx, %rcx ; \
              addq  $8, %rsp ; \
              cmpl  $CHECKLABEL, (%rcx) ; \
              jne 23f ; \
              addq  $0x8, %rcx ; \
              jmpq  *%rcx ; \
              23: movq $0xfea, %rax;

#endif

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
#define CHECKLABEL 0x48c98948

/* Macro for call */
#define CALLQ(x) callq x ; \
                 movq %rcx,%rcx ; \
                 movq %rdx,%rdx ; \
                 nop ; \
                 nop ;

/* Macro for start of function */
#define STARTFUNC movq %rcx,%rcx ; \
                  movq %rdx,%rdx ; \
                  nop ; \
                  nop ;

#define RETTARGET movq %rcx,%rcx ; \
                  movq %rdx,%rdx ; \
                  nop ; \
                  nop ;

/* Macro for return */
#define RETQ  movq  (%rsp), %rcx ; \
              movl  $0xffffff80, %edx ; \
              shlq   $32, %rdx ; \
              orq   %rdx, %rcx ; \
              addq  $8, %rsp ; \
              cmpl  $CHECKLABEL, (%rcx) ; \
              jne 23f ; \
              jmpq  *%rcx ; \
              xchg %bx, %bx ; \
              23: movq $0xfea, %rax;

#endif
              /* addq  $0x8, %rcx ; \ */

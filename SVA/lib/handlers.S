/*===- handlers.S - SVA Execution Engine Assembly --------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===----------------------------------------------------------------------===
 *
 * This is x86_64 assembly code used by the SVA Execution Engine.
 * It is in AT&T syntax, which means that the source operand is first and
 * the destination operand is second.
 *
 *===----------------------------------------------------------------------===
 */

/*****************************************************************************
 * Macros
 ****************************************************************************/

#include "offsets.h"
#include <sva/cfi.h>

/* FreeBSD segment selector for kernel code segment */
#define USERCS 0x03

/* Offsets for various fields in the CPU State Structure */
#define CPU_TSSP  0x08
#define CPU_NEWIC 0x10

/* Offsets for the TSS */
#define TSS_IST3 52

/*
 * Macro: TRAP
 *
 * Description:
 *  Create an assembly language routine that can dispatch the specified trap.
 *  This version is for traps that do not generate their own error code.
 */
#define TRAP(x) \
  .global trap##x ; \
  .type   trap##x, @function ; \
; \
trap##x: \
  /* Adjust the stack pointer so that we can push items using %ds */ \
  subq $16, %rsp ; \
 \
  /* Push a zero code */ \
  movq $0, 8(%rsp) ; \
\
  /* Push the trap number */ \
  movq $x, 0(%rsp) ; \
\
  /* Determine whether we interrupted user or supervisor mode execution. */ \
  cmpq $0x43, 24(%rsp) ; \
  jne 1f ; \
 \
  /* We came from user mode.  First switch to the kernel %GS register. */ \
  swapgs ; \
1: \
  /* Call the common trap code. */ \
  jmp Trap

/*
 * Macro: ECTRAP
 *
 * Description:
 *  Create an assembly language routine that can dispatch the specified trap.
 *  This version is for traps that generate their own error code.
 */
#define ECTRAP(x) \
  .global trap##x ; \
  .type   trap##x, @function ; \
; \
trap##x: \
  /* Adjust the stack pointer so that we can push items using %ds */ \
  subq $8, %rsp ; \
 \
  /* Push the trap number */ \
  movq $x, 0(%rsp) ; \
\
  /* Determine whether we interrupted user or supervisor mode execution. */ \
  cmpq $0x43, 24(%rsp) ; \
  jne 1f ; \
 \
  /* We came from user mode.  First switch to the kernel %GS register. */ \
  swapgs ; \
1: \
 \
  /* Call the common trap code. */ \
  jmp Trap

/*
 * Macro: INTERRUPT()
 * 
 * Description:
 *  Define the handler for an interrupt.  This is nearly identical to the 
 *  trap code.  It is really only different because it was different in the
 *  original SVA system; the new system does not need to distinguish between
 *  an interrupt and a trap.
 */
#define INTERRUPT(x) \
  .global interrupt##x ; \
  .type   interrupt##x, @function ; \
; \
interrupt##x: \
  /* Adjust the stack pointer so that we can push items using %ds */ \
  subq $16, %rsp ; \
 \
  /* Push a zero code */ \
  movq $0, 8(%rsp) ; \
\
  /* Push the trap number */ \
  movq $x, 0(%rsp) ; \
\
  /* Determine whether we interrupted user or supervisor mode execution. */ \
  cmpq $0x43, 24(%rsp) ; \
  jne 1f ; \
 \
  /* We came from user mode.  First switch to the kernel %GS register. */ \
  swapgs ; \
1: \
 \
  /* Call the common trap code. */ \
  jmp Trap

/*****************************************************************************
 * Data Section
 ****************************************************************************/
.data
.comm interrupt_table, 2048

/*****************************************************************************
 * Text Section
 ****************************************************************************/
.text

.global SVAbadtrap
.type SVAbadtrap, @function

.global SVAsyscall
.type SVAsyscall, @function

.global sc_ret
.type   sc_ret, @function

.global secmemtrap
.type secmemtrap, @function

.global secfreetrap
.type secfreetrap, @function

.global sva_syscall
.type sva_syscall, @function

/*
 * Function: SVAbadtrap
 *
 * Description:
 *  This function just generates a fault, allowing us to catch traps which SVA
 *  isn't fielding.
 */
SVAbadtrap:
  /* Cause a breakpoint */
  int $0x03

  /* Return from the interrupt */
  iretq

/*
 * Function: saveRegs
 *
 * Description:
 *  This function saves the registers into the interrupt context pointed to
 *  by %rbp.
 */
saveRegs:
  /* Save the registers into the interrupt context */
  movw %fs,  IC_FS(%rbp)
  movw %gs,  IC_GS(%rbp)
  movw %es,  IC_ES(%rbp)

  movq %rdi, IC_RDI(%rbp)
  movq %rsi, IC_RSI(%rbp)

  movq %rax, IC_RAX(%rbp)
  movq %rbx, IC_RBX(%rbp)
  movq %rcx, IC_RCX(%rbp)
  movq %rdx, IC_RDX(%rbp)

  movq %r8,   IC_R8(%rbp)
  movq %r9,   IC_R9(%rbp)
  movq %r10, IC_R10(%rbp)
  movq %r11, IC_R11(%rbp)
  movq %r12, IC_R12(%rbp)
  movq %r13, IC_R13(%rbp)
  movq %r14, IC_R14(%rbp)
  movq %r15, IC_R15(%rbp)

  retq

/*
 * Function: restoreRegs
 *
 * Description:
 *  Copy the registers from the interrupt context back on to the processor.
 */
restoreRegs:
#if 0
  movw IC_FS(%rbp), %fs
  movw IC_GS(%rbp), %gs
  movw IC_ES(%rbp), %es
#endif

  movq IC_RDI(%rbp), %rdi
  movq IC_RSI(%rbp), %rsi

  movq IC_RAX(%rbp), %rax
  movq IC_RBX(%rbp), %rbx
  movq IC_RCX(%rbp), %rcx
  movq IC_RDX(%rbp), %rdx

  movq  IC_R8(%rbp), %r8
  movq  IC_R9(%rbp), %r9
  movq IC_R10(%rbp), %r10
  movq IC_R11(%rbp), %r11
  movq IC_R12(%rbp), %r12
  movq IC_R13(%rbp), %r13
  movq IC_R14(%rbp), %r14
  movq IC_R15(%rbp), %r15

  retq

/*
 * Function: Trap
 *
 * Description:
 *  This code is common code for all trap and interrupt handlers.
 *
 * Preconditions:
 *  o The GS register should be pointing to the base of the interrupt context
 *    for the current processor.
 *  o The error code and trap number should have been pushed on to the stack. 
 */
Trap:
  /*
   * Switch to the stack segment.
   */
  subq $8, %rsp
  movq %rax, (%rsp)
  movw $0x28, %ax
  movw %ax, %ss
  movq (%rsp), %rax
  addq $8, %rsp

  /*
   * Save a copy of the interrupt context into SVA memory.
   */
  pushq %rbp
  pushq %r15
  pushq %r14
  pushq %r13
  pushq %r12
  pushq %r11
  pushq %r10
  pushq %r9
  pushq %r8

  pushq %rdx
  pushq %rcx
  pushq %rbx
  pushq %rax

  pushq %rsi
  pushq %rdi

  /* Save the segment registers */
  movw %ds, %ax
  pushw %ax
  movw %es, %ax
  pushw %ax
  pushw %gs
  pushw %fs

  /* Push the invoke frame pointer */
  pushq $0

  /*
   * Move the trap number into the %rdi register.
   */
  movq IC_TRAPNO(%rsp), %rdi

  /*
   * Move the address causing the fault (which may or may not be applicable)
   * into the %rsi register to make it the second argument.
   */
  movq %cr2, %rsi

  /*
   * Save the address of the current interrupt context into this processor's
   * CPU state.
   */
  movq %gs:0x260, %rbp
  movq %rsp, CPU_NEWIC(%rbp)

  /*
   * Modify the value in the Task State Segment (TSS) so that the next trap
   * or interrupt on this processor saves state into the next interrupt
   * context.
   */
  movq CPU_TSSP(%rbp), %rbx
  movq %rsp, TSS_IST3(%rbx)

  /*
   * Adjust it to point to the first byte of the current interrupt context.
   */
  subq $0x10, TSS_IST3(%rbx)

  /*
   * Switch to the kernel stack.  If coming from user space, use the kernel
   * stack pointer specified by the kernel.  Otherwise, use the previous
   * kernel stack pointer.
   *
   * NOTE: The offset to the code segment is hard-coded here because I couldn't
   *       get the macro magic working properly.  If the interrupt context
   *       layout changes, the offset used to look for the code segment will
   *       also need to change.
   */
  movq CPU_TSSP(%rbp), %rbp
  cmpw $0x43, 0xa0(%rsp)
  cmoveq 4(%rbp), %rsp
  cmovneq IC_RSP(%rsp), %rsp

  /*
   * Call the trap handler registered by the OS for this trap.
   */
  movq $interrupt_table, %rax
  callq *(%rax,%rdi,8)
  RETTARGET

  /*
   * Switch the stack pointer back to the interrupt context.
   */
  movq %gs:0x260, %rbp
  movq CPU_NEWIC(%rbp), %rsp

  /*
   * Pop off the most recent interrupt context.  This requires modifying
   * the newCurrentIC field of the CPUState as well as modifying the IST
   * in the TSS.
   */
  addq $IC_SIZE, CPU_NEWIC(%rbp)
  movq CPU_TSSP(%rbp), %rbx
  addq $IC_SIZE, TSS_IST3(%rbx)

  /*
   * Copy the registers from the interrupt context back on to the processor.
   */
#if 0
  movw IC_FS(%rsp), %fs
  movw IC_ES(%rsp), %es
  movw IC_DS(%rsp), %ax
  movw %ax, %ds
#else
  movw IC_FS(%rsp), %ax
  movw IC_ES(%rsp), %bx
  movw IC_DS(%rsp), %cx
#if 0
  andl $0xffff, %eax
  andl $0xffff, %ebx
  andl $0xffff, %ecx
#endif
  movw %ax, %fs
  movw %bx, %es
  movw %cx, %ds
#endif

  movq IC_RDI(%rsp), %rdi
  movq IC_RSI(%rsp), %rsi

  movq IC_RAX(%rsp), %rax
  movq IC_RBX(%rsp), %rbx
  movq IC_RCX(%rsp), %rcx
  movq IC_RDX(%rsp), %rdx

  movq  IC_R8(%rsp), %r8
  movq  IC_R9(%rsp), %r9
  movq IC_R10(%rsp), %r10
  movq IC_R11(%rsp), %r11
  movq IC_R12(%rsp), %r12
  movq IC_R13(%rsp), %r13
  movq IC_R14(%rsp), %r14
  movq IC_R15(%rsp), %r15
  movq IC_RBP(%rsp), %rbp

  /*
   * Remove the current interrupt context.
   */
  addq $0x98, %rsp

  /* Determine whether we interrupted user or supervisor mode execution. */
  cmpq $0x43, 8(%rsp)
  jne 1f

  /* We came from user mode.  First switch to the kernel %GS register. */
  swapgs

1:
  /*
   * Return to the calling code.  On x86_64, this will restore the stack
   * pointer regardless of whether we came from user mode or kernel mode.
   */
  iretq

/*
 * Trap: SVAsyscall
 *
 * Description:
 *  This trap handles system call entry.
 *
 * Preconditions:
 *  o The GS register should be pointing to the base of the interrupt context
 *    for the current processor.
 *
 * Notes:
 *  o This function is called by the processor by the syscall instruction.
 *    When we enter, we are still running on the application's stack.
 *
 *  o We assume that the syscall instruction was executed in user-mode.  SVA
 *    should ensure that syscall is never generated for kernel code and that
 *    the kernel cannot jump to user-space code containing the syscall
 *    sequence.
 *
 *  o The SVA CFI checks should prevent the kernel from jumping to a syscall
 *    instruction that exists in kernel code because it will violate the
 *    assumption that we need to use swapgs to configure the %GS register.
 */
SVAsyscall:
  /* We came from user mode.  First switch to the kernel %GS register. */
  swapgs

  /*
   * Turn off the upper bit in the system call number (stored in %rax).
   */
  andl $0x7fffffff, %eax

  /*
   * Save the stack pointer (%rsp) for the application.
   */
  pushq %rsp

  /*
   * Save a few registers so that we have some with which to work.
   */
  pushq %rbp
  pushq %rdi
  pushq %rsi

  /*
   * Get the location of the interrupt context within the current processor's
   * CPUState and switch over to that stack.
   */
  movq %gs:0x260, %rdi
  movq %gs:0x260, %rbp
  addq $0x1a20, %rbp
  movq %rsp, %rsi
  movq %rbp, %rsp

  /*
   * The stack pointer is now pointing into the interrupt context.
   */

  /* Push two dummy values and a dummy stack segment */
  pushq $0
  pushq $0
  pushq $0

  /* Push the user-space stack pointer (%rsp) */
  pushq 0x18(%rsi)

  /* Push the user-space status flags */
  pushq %r11

  /* Push the user-space code segment */
  pushq $USERCS

  /* Push the user-space program counter (%rip) */
  pushq %rcx

  /* Push a zero code */
  pushq $0

  /* Push a dummy trap number */
  pushq $0

  /*
   * Save a copy of the interrupt context into SVA memory.
   */
  pushq 0x10(%rsi)
  pushq %r15
  pushq %r14
  pushq %r13
  pushq %r12
  pushq %r11
  pushq %r10
  pushq %r9
  pushq %r8

  pushq %rdx
  pushq %rcx
  pushq %rbx
  pushq %rax

  pushq 0x00(%rsi)
  pushq 0x08(%rsi)

  movw %ds, %ax
  movw %es, %bx
  pushw %ax
  pushw %bx
  pushw %gs
  pushw %fs

  pushq $0

  /*
   * Save the address of the current interrupt context into this processor's
   * CPU state.
   */
  movq %gs:0x260, %rbp
  movq %rsp, CPU_NEWIC(%rbp)

  /*
   * Modify the value in the Task State Segment (TSS) so that the next trap
   * or interrupt on this processor saves state into the next interrupt
   * context.
   */
  movq CPU_TSSP(%rbp), %rbx
  movq %rsp, TSS_IST3(%rbx)

  /*
   * Adjust it to point to the first byte of the current interrupt context.
   */
  subq $0x10, TSS_IST3(%rbx)

  /*
   * Switch to the kernel stack.  Since we always come from user space, 
   * switch to the kernel stack pointer specified by the kernel.
   */
  movq CPU_TSSP(%rbp), %rsp

  /*
   * Call the system software system call handler.
   */
  callq sva_syscall
sc_ret:
  RETTARGET

  /*
   * Switch the stack pointer back to the interrupt context.
   */
  movq %gs:0x260, %rbp
  movq CPU_NEWIC(%rbp), %rsp

  /*
   * Pop off the most recent interrupt context.  This requires modifying
   * the newCurrentIC field of the CPUState as well as modifying the IST
   * in the TSS.
   */
  addq $IC_SIZE, CPU_NEWIC(%rbp)
  movq CPU_TSSP(%rbp), %rbx
  addq $IC_SIZE, TSS_IST3(%rbx)

  /*
   * Copy the registers from the interrupt context back on to the processor.
   */
  movw IC_FS(%rsp), %cx
  movw IC_ES(%rsp), %bx
  movw IC_DS(%rsp), %ax
  movw %cx, %fs
  movw %bx, %es
  movw %ax, %ds

  movq IC_RDI(%rsp), %rdi
  movq IC_RSI(%rsp), %rsi

  movq IC_RAX(%rsp), %rax
  movq IC_RBX(%rsp), %rbx
  movq IC_RIP(%rsp), %rcx   /* Put the %rip in %rcx for sysret instruction */
  movq IC_RDX(%rsp), %rdx

  movq  IC_R8(%rsp), %r8
  movq  IC_R9(%rsp), %r9
  movq IC_R10(%rsp), %r10
  movq IC_RFLAGS(%rsp), %r11 /* Put the rflags back into %r11 for sysret */
  movq IC_R12(%rsp), %r12
  movq IC_R13(%rsp), %r13
  movq IC_R14(%rsp), %r14
  movq IC_R15(%rsp), %r15
  movq IC_RBP(%rsp), %rbp

  /*
   * Restore the user-space stack pointer.
   */
  movq IC_RSP(%rsp), %rsp

  /* We came from user mode.  First switch to the kernel %GS register. */
  swapgs

  /*
   * Return to the calling code.
   */
  sysretq

/*
 * Trap: secmemtrap
 *
 * Description:
 *  This trap handles secure memory allocations.
 *
 * Inputs:
 *  %rdi - This register should hold the size, in bytes, of secure memory to
 *         allocate.
 *
 * Return value:
 *  %rax - This register should hold a pointer to the allocated memory.
 */
secmemtrap:
  /* Use the swapgs instruction to switch to the kernel map */
  swapgs

  /* Call the secure memory allocator function */
  call  allocSecureMemory
  RETTARGET

  /* Use the swapgs instruction to switch back to user mode */
  swapgs

  /* Return from the trap */
  iretq

/*
 * Trap: secfreetrap
 *
 * Description:
 *  This trap handles secure memory deallocations.
 *
 * Inputs:
 *  %rdi - The pointer to the first byte of secure memory to deallocate.
 *  %rsi - This register should hold the size, in bytes, of secure memory to
 *         allocate.
 */
secfreetrap:
  /* Use the swapgs instruction to switch to the kernel map */
  swapgs

  /* Call the secure memory deallocator function */
  call  freeSecureMemory
  RETTARGET

  /* Use the swapgs instruction to switch back to user mode */
  swapgs

  /* Return from the trap */
  iretq

/* Define the trap handlers */
TRAP(0)
TRAP(1)
TRAP(2)
TRAP(3)
TRAP(4)
TRAP(5)
TRAP(6)
TRAP(7)
ECTRAP(8)
TRAP(9)
ECTRAP(10)
ECTRAP(11)
ECTRAP(12)
ECTRAP(13)
ECTRAP(14)
TRAP(15)
TRAP(16)
ECTRAP(17)
TRAP(18)
TRAP(19)
TRAP(20)
TRAP(21)
TRAP(22)
TRAP(23)
TRAP(24)
TRAP(25)
TRAP(26)
TRAP(27)
TRAP(28)
TRAP(29)
TRAP(30)
TRAP(31)

/*
 * Old PC IRQ Interrupts
 *  33 - Keyboard
 *  38 - Floppy Disk
 *  44 - PS/2 Mouse
 */
INTERRUPT(32)
INTERRUPT(33)
INTERRUPT(34)
INTERRUPT(35)
INTERRUPT(36)
INTERRUPT(37)
INTERRUPT(38)
INTERRUPT(39)
INTERRUPT(40)
INTERRUPT(41)
INTERRUPT(42)
INTERRUPT(43)
INTERRUPT(44)
INTERRUPT(45)
INTERRUPT(46)
INTERRUPT(47)
INTERRUPT(48)

/*
 * IO-APIC Interrupts
 */
INTERRUPT(49)
INTERRUPT(50)
INTERRUPT(51)
INTERRUPT(52)
INTERRUPT(54)
INTERRUPT(57)
INTERRUPT(65)
INTERRUPT(73)
INTERRUPT(89)
INTERRUPT(121)
INTERRUPT(137)
INTERRUPT(153)
INTERRUPT(161)

/*
 * New Local APIC Interrupts
 *  239     : Local APIC Timer
 *  251-255 : SMP APIC Vectors
 */
INTERRUPT(239)
INTERRUPT(251)
INTERRUPT(252)
INTERRUPT(253)
INTERRUPT(254)
INTERRUPT(255)



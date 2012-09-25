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

/* FreeBSD segment selector for kernel code segment */
#define USERCS 0x03

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
  /* Push a zero code */ \
  pushq $0 ; \
\
  /* Push the trap number */ \
  pushq $x ; \
\
  /* Determine whether we interrupted user or supervisor mode execution. */ \
  testw $USERCS, 24(%rsp) ; \
  jz 1f ; \
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
  /* Push the trap number */ \
  pushq $x ; \
\
  /* Determine whether we interrupted user or supervisor mode execution. */ \
  testw $USERCS, 24(%rsp) ; \
  jz 1f ; \
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
  /* Push a zero code */ \
  pushq $0 ; \
\
  /* Push the trap number */ \
  pushq $x ; \
\
  /* Determine whether we interrupted user or supervisor mode execution. */ \
  testw $USERCS, 24(%rsp) ; \
  jz 1f ; \
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

.global SVAsysret
.type SVAsysret, @function

.global secmemtrap
.type secmemtrap, @function

.global secfreetrap
.type secfreetrap, @function

/*
 * Function: SVAbadtrap
 *
 * Description:
 *  This function just generates a fault, allowing us to catch traps which SVA
 *  isn't fielding.
 */
SVAbadtrap:
  movq $0xbeefbeef, %rbx
  movq %rax, 0xbad
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
  movw %fs,  0x10(%rbp)
  movw %gs,  0x12(%rbp)
  movw %es,  0x14(%rbp)

  movq %rdi, 0x18(%rbp)
  movq %rsi, 0x20(%rbp)

  movq %rax, 0x28(%rbp)
  movq %rbx, 0x30(%rbp)
  movq %rcx, 0x38(%rbp)
  movq %rdx, 0x40(%rbp)

  movq %r8,  0x48(%rbp)
  movq %r9,  0x50(%rbp)
  movq %r10, 0x58(%rbp)
  movq %r11, 0x60(%rbp)
  movq %r12, 0x68(%rbp)
  movq %r13, 0x70(%rbp)
  movq %r14, 0x78(%rbp)
  movq %r15, 0x80(%rbp)

  retq

/*
 * Function: restoreRegs
 *
 * Description:
 *  Copy the registers from the interrupt context back on to the processor.
 */
restoreRegs:
#if 0
  movw 0x10(%rbp), %fs
  movw 0x12(%rbp), %gs
  movw 0x14(%rbp), %es
#endif

  movq 0x18(%rbp), %rdi
  movq 0x20(%rbp), %rsi

  movq 0x28(%rbp), %rax
  movq 0x30(%rbp), %rbx
  movq 0x38(%rbp), %rcx
  movq 0x40(%rbp), %rdx

  movq 0x48(%rbp), %r8
  movq 0x50(%rbp), %r9
  movq 0x58(%rbp), %r10
  movq 0x60(%rbp), %r11
  movq 0x68(%rbp), %r12
  movq 0x70(%rbp), %r13
  movq 0x78(%rbp), %r14
  movq 0x80(%rbp), %r15

  ret

/*
 * Function: Trap
 *
 * Description:
 *  This code is common code for all trap handlers that handle traps with
 *  no x86_64 error code.
 *
 * Preconditions:
 *  o The GS register should be pointing to the base of the interrupt context
 *    for the current processor.
 *  o The error code and trap number should have been pushed on to the stack. 
 */
Trap:
  /*
   * Get a pointer to the current processor's interrupt context.
   */
  pushq %rbp
  movq %gs:0x260, %rbp
  movq (%rbp), %rbp

  /*
   * Save a copy of the interrupt context into SVA memory.
   */
  callq saveRegs

  /* Increment the interrupt context pointer */
  callq incrementNextIC

  /*
   * Copy the registers saved by the processor into the user-space interupt
   * context.
   */
  movq 0x00(%rsp), %r8
  movq 0x08(%rsp), %rdi /* Use %rdi to make argument setup faster */
  movq 0x10(%rsp), %r10
  movq 0x18(%rsp), %r11
  movq 0x20(%rsp), %r12
  movq 0x28(%rsp), %r13
  movq 0x30(%rsp), %r14
  movq 0x38(%rsp), %r15
  movq %r8,  0x88(%rbp)
  movq %rdi, 0x90(%rbp)
  movq %r10, 0x98(%rbp)
  movq %r11, 0xa0(%rbp)
  movq %r12, 0xa8(%rbp)
  movq %r13, 0xb0(%rbp)
  movq %r14, 0xb8(%rbp)
  movq %r15, 0xc0(%rbp)

  /*
   * Call the trap handler registered by the OS for this trap.
   */
  movq $interrupt_table, %rax
  callq *(%rax,%rdi,8)

  /*
   * Copy changes made to the interrupt context back on to the kernel stack.
   */
  movq 0x88(%rbp), %r8
  movq 0x90(%rbp), %r9
  movq 0x98(%rbp), %r10
  movq 0xa0(%rbp), %r11
  movq 0xa8(%rbp), %r12
  movq 0xb0(%rbp), %r13
  movq 0xb8(%rbp), %r14
  movq 0xc0(%rbp), %r15
  movq %r8,  0x00(%rsp)
  movq %r9,  0x08(%rsp)
  movq %r10, 0x10(%rsp)
  movq %r11, 0x18(%rsp)
  movq %r12, 0x20(%rsp)
  movq %r13, 0x28(%rsp)
  movq %r14, 0x30(%rsp)
  movq %r15, 0x38(%rsp)

  /* Decrement the interrupt context pointer */
  call decrementNextIC

  /*
   * Copy the registers from the interrupt context back on to the processor.
   */
  call restoreRegs

  /*
   * Remove the saved %rbp from the stack.
   */
  popq %rbp

  /*
   * Remove the error code and trap number.
   */
  addq $16, %rsp

  /* Determine whether we interrupted user or supervisor mode execution. */
  testw $USERCS, 8(%rsp)
  jz 1f

  /* We came from user mode.  First switch to the kernel %GS register. */
  swapgs

1:
  /*
   * Return to the calling code.
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
 *  o The error code and trap number should have been pushed on to the stack. 
 */
SVAsyscall:
  /*
   * Get a pointer to the current processor's interrupt context.
   */
  pushq %rbp
  movq %gs:0x260, %rbp
  movq (%rbp), %rbp

  /*
   * Set the next link to NULL (the user-space interrupt context should always
   * be the first in the interrupt context chain).
   */
  movq $0, 0x00(%rbp)

  /*
   * Save a copy of the interrupt context into SVA memory.
   */
  callq saveRegs

  /*
   * Copy the registers saved by the processor into the user-space interupt
   * context.
   */
  movq 0x10(%rsp), %rax
  movq %rax, 0xa0(%rbp)
  movq 0x18(%rsp), %rax
  movq %rax, 0xa8(%rbp)
  movq 0x20(%rsp), %rax
  movq %rax, 0xb0(%rbp)
  movq 0x28(%rsp), %rax
  movq %rax, 0xb8(%rbp)
  movq 0x30(%rsp), %rax
  movq %rax, 0xc0(%rbp)

  /*
   * Restore %rax from the saved register state.
   */
  movq 0x28(%rbp), %rax

  /*
   * Save a copy of the %rbp register into the interrupt context and then
   * restore it to its saved value.
   */
  popq 0x88(%rbp)
  movq 0x88(%rbp), %rbp

  ret

SVAsysret:
  /*
   * Get a pointer to the current processor's interrupt context.
   */
  movq %gs:0x260, %rbp
  movq (%rbp), %rbp

  /*
   * Copy the registers from the interrupt context back on to the processor.
   */
  call restoreRegs

  /* Restore %rbp last */
  movq 0x88(%rbp), %rbp
  ret

  /* Exit the system call */
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
TRAP(15)
TRAP(16)
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



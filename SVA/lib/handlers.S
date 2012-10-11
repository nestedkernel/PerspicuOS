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

/* Offsets for various fields in the SVA Interrupt Context */
#define IC_INVOKEP 0x00
#define IC_FS      0x08
#define IC_GS      0x0a
#define IC_ES      0x0c

#define IC_RDI     0x10
#define IC_RSI     0x18

#define IC_RAX     0x20
#define IC_RBX     0x28
#define IC_RCX     0x30
#define IC_RDX     0x38

#define IC_R8      0x40
#define IC_R9      0x48
#define IC_R10     0x50
#define IC_R11     0x58
#define IC_R12     0x60
#define IC_R13     0x68
#define IC_R14     0x70
#define IC_R15     0x78

#define IC_RBP     0x80

#define IC_TRAPNO  0x88

#define IC_CODE    0x90
#define IC_RIP     0x98
#define IC_CS      0xa0
#define IC_RFLAGS  0xa8
#define IC_RSP     0xb0
#define IC_SS      0xb8

/* Offsets for various fields in the CPU State Structure */
#define CPU_TSSP  0x08
#define CPU_NEWIC 0x10

/*
 * Macro: NEWTRAP
 *
 * Description:
 *  Create an assembly language routine that can dispatch the specified trap.
 *  This version is for traps that do not generate their own error code.
 */
#define NEWTRAP(x) \
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
  jmp NewTrap


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
 * Function: NewTrap
 *
 * Description:
 *  This code is common code for all trap and interrupt handlers.
 *
 * Preconditions:
 *  o The GS register should be pointing to the base of the interrupt context
 *    for the current processor.
 *  o The error code and trap number should have been pushed on to the stack. 
 */
NewTrap:
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

  pushw $0
  movw  %es, 0(%rsp)
  subq $2, %rsp
  pushw %gs
  pushw %fs

  pushq $0
#if 0
  /* Interrupt Context next field */
  pushq $0
#endif

  /*
   * Move the trap number into the %rdi register.
   */
  movq IC_TRAPNO(%rsp), %rdi

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
  movq %rsp, 52(%rbx)

#if 0
  /*
   * Adjust it to point to the first byte of the current interrupt context
   */
  addq $8, 52(%rbx)
#endif

  /*
   * Switch to the kernel stack.  If coming from user space, use the kernel
   * stack pointer specified by the kernel.  Otherwise, use the previous
   * kernel stack pointer.
   */
  movq CPU_TSSP(%rbp), %rbp
  cmpw $USERCS, 0xa8(%rsp)
  cmoveq 4(%rbp), %rsp
  cmovneq IC_RSP(%rsp), %rsp

  /*
   * Call the trap handler registered by the OS for this trap.
   */
  movq $interrupt_table, %rax
  callq *(%rax,%rdi,8)

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
  addq $0xc0, CPU_NEWIC(%rbp)
  movq CPU_TSSP(%rbp), %rbx
  addq $0xc0, 52(%rbx)

  /*
   * Copy the registers from the interrupt context back on to the processor.
   */
#if 0
  movw IC_FS(%rsp), %fs
  movw IC_GS(%rsp), %gs
  movw IC_ES(%rsp), %es
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
#if 0
  addq $0xa0, %rsp
#else
  addq $0x98, %rsp
#endif

  /* Determine whether we interrupted user or supervisor mode execution. */
  testw $USERCS, 8(%rsp)
  jz 1f

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
NEWTRAP(0)
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



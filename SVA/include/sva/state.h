/*===- state.h - SVA Interrupts   -----------------------------------------===
 * 
 *                     The LLVM Compiler Infrastructure
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This header files defines functions and macros used by the SVA Execution
 * Engine for managing processor state.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef _SVA_STATE_H
#define _SVA_STATE_H

#include <sys/types.h>

#include "sva/x86.h"
#if 0
#include "sva/util.h"
#include "sva/exceptions.h"
#endif

/* Processor privilege level */
typedef unsigned char priv_level_t;

/* Stack Pointer Typer */
typedef uintptr_t * sva_sp_t;

/*
 * Structure: icontext_t
 *
 * Description:
 *  This structure is what is saved by the Execution Engine when an interrupt,
 *  exception, or system call occurs.  It must ensure that all state that is
 *    (a) Used by the interrupted process, and
 *    (b) Potentially used by the kernel
 *  is saved and accessible until *the handler routine returns*.  On the
 *  x86_64, this means that we have to save *all* GPR's.
 *
 *  As the Execution Engine gets smarter, we might be able to skip saving some
 *  of these, or on hardware with shadow register sets, we might be able to
 *  forgo it at all.
 *
 * Notes:
 *  o) This structure *must* have a length equal to an even number of quad
 *     words.  The SVA interrupt handling code depends upon this behavior.
 */
typedef struct sva_icontext {
  /* Invoke Pointer */
  void * invokep;                     // 0x00

  /* Segment selector registers */
  unsigned short fs;                  // 0x08
  unsigned short gs;
  unsigned short es;
  unsigned short ds;

  unsigned long rdi;                  // 0x10
  unsigned long rsi;                  // 0x18

  unsigned long rax;                  // 0x20
  unsigned long rbx;                  // 0x28
  unsigned long rcx;                  // 0x30
  unsigned long rdx;                  // 0x38

  unsigned long r8;                   // 0x40
  unsigned long r9;                   // 0x48
  unsigned long r10;                  // 0x50
  unsigned long r11;                  // 0x58
  unsigned long r12;                  // 0x60
  unsigned long r13;                  // 0x68
  unsigned long r14;                  // 0x70
  unsigned long r15;                  // 0x78

  /*
   * Keep this register right here.  We'll use it in assembly code, and we
   * place it here for easy saving and recovery.
   */
  unsigned long rbp;                  // 0x80

  /* Hardware trap number */
  unsigned long trapno;               // 0x88

  /*
   * These values are automagically saved by the x86_64 hardware upon an
   * interrupt or exception.
   */
  unsigned long code;                 // 0x90
  unsigned long rip;                  // 0x98
  unsigned long cs;                   // 0xa0
  unsigned long rflags;               // 0xa8
  unsigned long * rsp;                // 0xb0
  unsigned long ss;                   // 0xb8

  /* Flags whether the interrupt context is valid */
  unsigned long valid;                // 0xc0
  unsigned long start;                // 0xc8
} __attribute__ ((aligned (16))) sva_icontext_t;

typedef struct
{
  unsigned int state[7];
  unsigned int fp_regs[20];
} sva_fp_state_t;

/*
 * Structure: sva_integer_state_t
 *
 * Description:
 *  This is all of the hardware state needed to represent an LLVM program's
 *  control flow, stack pointer, and integer registers.
 *
 * TODO:
 *  The stack pointer should probably be removed.
 */
typedef struct {
  /* Invoke Pointer */
  void * invokep;                     // 0x00

  /* Segment selector registers */
  unsigned short fs;                  // 0x08
  unsigned short gs;
  unsigned short es;
  unsigned short ds;

  unsigned long rdi;                  // 0x10
  unsigned long rsi;                  // 0x18

  unsigned long rax;                  // 0x20
  unsigned long rbx;                  // 0x28
  unsigned long rcx;                  // 0x30
  unsigned long rdx;                  // 0x38

  unsigned long r8;                   // 0x40
  unsigned long r9;                   // 0x48
  unsigned long r10;                  // 0x50
  unsigned long r11;                  // 0x58
  unsigned long r12;                  // 0x60
  unsigned long r13;                  // 0x68
  unsigned long r14;                  // 0x70
  unsigned long r15;                  // 0x78

  /*
   * Keep this register right here.  We'll use it in assembly code, and we
   * place it here for easy saving and recovery.
   */
  unsigned long rbp;                  // 0x80

  /* Hardware trap number */
  unsigned long trapno;               // 0x88

  /*
   * These values are automagically saved by the x86_64 hardware upon an
   * interrupt or exception.
   */
  unsigned long code;                 // 0x90
  unsigned long rip;                  // 0x98
  unsigned long cs;                   // 0xa0
  unsigned long rflags;               // 0xa8
  unsigned long * rsp;                // 0xb0
  unsigned long ss;                   // 0xb8

  /* Flag for whether the integer state is valid */
  unsigned long valid;                // 0xc0

  /* Store another RIP value for the second return */
  unsigned long hackRIP;              // 0xc8

  /* Kernel stack pointer */
  unsigned long kstackp;              // 0xd0

  /* CR3 register */
  unsigned long cr3;                  // 0xd8

  /* Current interrupt context location */
  sva_icontext_t * currentIC;         // 0xe0

  /* Current setting of IST3 in the TSS */
  unsigned long ist3;                // 0xe8

  /* Floating point state */
  sva_fp_state_t fpstate;            // 0xf0
} sva_integer_state_t;

/*
 * Structure: invoke_frame
 *
 * Description:
 *  This structure contains all of the information necessary to return
 *  state to the exceptional basic block when an unwind needs to be performed.
 */
struct invoke_frame
{
  unsigned int ebp;
  unsigned int ebx;
  unsigned int esi;
  unsigned int edi;
                                                                                
  struct invoke_frame * next;
  unsigned int cpinvoke;
};

/* The maximum number of interrupt contexts per CPU */
static const unsigned char maxIC = 32;

/*
 * Struct: SVAThread
 *
 * Description:
 *  This structure describes one "thread" of control in SVA.  It is an
 *  interrupt context, an integer state, and a flag indicating whether the
 *  state is available or free.
 */
struct SVAThread {
  /* Interrupt contexts for this thread */
  sva_icontext_t interruptContexts[maxIC + 1];

  /* Interrupt contexts used for signal handler dispatch */
  sva_icontext_t savedInterruptContexts[maxIC + 1];

  /* Integer state for this thread for context switching */
  sva_integer_state_t integerState;

  /* Index of currently available saved Interrupt Context */
  unsigned char savedICIndex;

  /* Flag whether the thread is in use */
  unsigned char used;
} __attribute__ ((aligned (16)));

/*
 * Structure: CPUState
 *
 * Description:
 *  This is a structure containing the per-CPU state of each processor in the
 *  system.  We gather this here so that it's easy to find them from the %GS
 *  register.
 */
struct CPUState {
  /* Pointer to the thread currently on the processor */
  struct SVAThread * currentThread;

  /* Per-processor TSS segment */
  tss_t * tssp;

  /* New current interrupt Context */
  sva_icontext_t * newCurrentIC;
};

/*
 * Function: get_cpuState()
 *
 * Description:
 *  This function finds the CPU state for the current process.
 */
static inline struct CPUState *
getCPUState(void) {
  /*
   * Use an offset from the GS register to look up the processor CPU state for
   * this processor.
   */
  struct CPUState * cpustate;
  __asm__ __volatile__ ("movq %%gs:0x260, %0\n" : "=r" (cpustate));
  return cpustate;
}

/*
 * Intrinsic: sva_was_privileged()
 *
 * Description:
 *  This intrinsic flags whether the most recent interrupt context was running
 *  in a privileged state before the interrupt/exception occurred.
 *
 * Return value:
 *  true  - The processor was in privileged mode when interrupted.
 *  false - The processor was in user-mode when interrupted.
 */
static inline unsigned char
sva_was_privileged (void) {
  /* Constant mask for user-space code segments */
  const uintptr_t userCodeSegmentMask = 0x03;

  /*
   * Lookup the most recent interrupt context for this processor and see
   * if it's code segment has the user-mode segment bits turned on.  Apparently
   * all FreeBSD user-space code segments have 3 as the last digit.
   */
  return (!((getCPUState()->newCurrentIC->cs) & userCodeSegmentMask));
}

/*
 * Intrinsic: sva_icontext_getpc()
 *
 * Description:
 *  Get the native code program counter value out of the interrupt context.
 */
static inline uintptr_t
sva_icontext_getpc (void) {
  struct CPUState * cpuState = getCPUState();
  return cpuState->newCurrentIC->rip;
}

/*
 * FIXME: This is a hack because we don't have invokememcpy() implemented yet.
 */
static inline void
sva_icontext_setrip (uintptr_t pc) {
  struct CPUState * cpuState = getCPUState();
  cpuState->newCurrentIC->rip = pc;
  return;
}

#if 0
/* Prototypes for Execution Engine Functions */
extern unsigned char * sva_get_integer_stackp  (void * integerp);
extern void            sva_set_integer_stackp  (sva_integer_state_t * p, sva_sp_t sp);

extern void sva_push_syscall   (unsigned int sysnum, void * exceptp, void * fn);

extern void sva_load_kstackp (sva_sp_t);
extern sva_sp_t sva_save_kstackp (void);

extern void   sva_unwind      (sva_icontext_t * p);
extern unsigned int  sva_invoke      (unsigned int * retvalue,
                                       void *f, int arg1, int arg2, int arg3);

/*****************************************************************************
 * Global State
 ****************************************************************************/
#endif

extern uintptr_t sva_swap_integer  (uintptr_t new, uintptr_t * state);
extern uintptr_t sva_init_stack (unsigned char * sp,
                                 uintptr_t length,
                                 void * f,
                                 uintptr_t arg1,
                                 uintptr_t arg2,
                                 uintptr_t arg3);
extern void sva_reinit_icontext (void *, unsigned char, uintptr_t, uintptr_t);

#if 0
extern void *       sva_declare_stack (void * p, unsigned size);
extern void         sva_release_stack (void * p);
#endif

/*****************************************************************************
 * Individual State Components
 ****************************************************************************/

extern void sva_ipush_function5 (void (*f)(uintptr_t, uintptr_t, uintptr_t),
                                 uintptr_t p1,
                                 uintptr_t p2,
                                 uintptr_t p3,
                                 uintptr_t p4,
                                 uintptr_t p5);

extern void * sva_ialloca (uintptr_t size, uintptr_t alignment, void * initp);

#if 0
extern inline unsigned char
sva_is_privileged  (void)
{
  unsigned int cs;
  __asm__ __volatile__ ("movl %%cs, %0\n" : "=r" (cs));
  return ((cs & 0x10) == 0x10);
}

/*
 * Intrinsic: sva_save_stackp ()
 *
 * Description:
 *  Return the current processor stack pointer to the caller.
 */
extern inline sva_sp_t
sva_save_stackp (void)
{
  unsigned int value;
  __asm__ ("movl %%esp, %0\n" : "=r" (value));
  return (void *)(value);
}

/*
 * Intrinsic: sva_load_stackp ()
 *
 * Description:
 *  Load on to the processor the stack pointer specified.
 */
extern inline void
sva_load_stackp  (sva_sp_t p)
{
  __asm__ __volatile__ ("movl %0, %%esp\n" :: "r" (p));
  return;
}

extern inline struct invoke_frame * gip;

/*
 * Intrinsic: sva_load_invoke()
 *
 * Description:
 *  Set the top of the invoke stack.
 */
extern inline void
sva_load_invoke (void * p)
{
  gip = p;
  return;
}

/*
 * Intrinsic: sva_save_invoke()
 *
 * Description:
 *  Save the current value of the top of the invoke stack.
 */
extern inline void *
sva_save_invoke (void)
{
  return gip;
}

extern inline unsigned int
sva_icontext_load_retvalue (void * icontext)
{
  return (((sva_icontext_t *)(icontext))->eax);
}

extern inline void
sva_icontext_save_retvalue (void * icontext, unsigned int value)
{
  (((sva_icontext_t *)(icontext))->eax) = value;
}

/*
 * Intrinsic: sva_get_icontext_stackp ()
 *
 * Description:
 *  Return the stack pointer that is saved within the specified interrupt
 *  context structure.
 */
extern inline unsigned char *
sva_get_icontext_stackp (void * icontext)
{
  /*
   * Verify that this interrupt context has a stack pointer.
   */
  if (sva_is_privileged () && sva_was_privileged(icontext))
  {
    __asm__ __volatile__ ("int %0\n" :: "i" (sva_state_exception));
  }

  return (((sva_icontext_t *)icontext)->esp);
}

/*
 * Intrinsic: sva_set_icontext_stackp ()
 *
 * Description:
 *  Sets the stack pointer that is saved within the specified interrupt
 *  context structure.
 */
extern inline void
sva_set_icontext_stackp (void * icontext, void * stackp)
{
  /*
   * Verify that this interrupt context has a stack pointer.
   */
#if 0
  if (sva_is_privileged () && sva_was_privileged(icontext))
  {
    __asm__ __volatile__ ("int %0\n" :: "i" (sva_state_exception));
  }
#endif

  (((sva_icontext_t *)icontext)->esp) = stackp;
  return;
}

/*
 * Intrinsic: sva_iset_privileged ()
 *
 * Description:
 *  Change the state of the interrupt context to have come from an unprivileged
 *  state.
 */
extern inline void
sva_iset_privileged (void * icontext, unsigned char privileged)
{
  sva_icontext_t * p = icontext;
  /* Old interrupt flags */
  unsigned int eflags;

  /*
   * Disable interrupts.
   */
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));

  if (privileged)
  {
    p->cs = 0x10;
    p->ds = 0x18;
    p->es = 0x18;
  }
  else
  {
    p->cs = 0x23;
    p->ds = 0x2B;
    p->es = 0x2B;
    p->ss = 0x2B;
  }

  /*
   * Re-enable interrupts.
   */
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");

  return;
}

extern inline long long
sva_save_tsc (void)
{
  long long tsc;

  __asm__ __volatile__ ("rdtsc\n" : "=A" (tsc));
  return tsc;
}

extern inline void
sva_load_tsc (long long tsc)
{
  __asm__ __volatile__ ("wrmsr\n" :: "A" (tsc), "c" (0x10));
}

extern inline unsigned int
sva_invokememcpy (void * to, const void * from, unsigned long count)
{
  /* The invoke frame placed on the stack */
  struct invoke_frame frame;
                                                                                
  /* The invoke frame pointer */
  extern struct invoke_frame * gip;
                                                                                
  /* Return value */
  unsigned int ret = 0;
                                                                                
  /* Mark the frame as being used for a memcpy */
  frame.cpinvoke = 1;
  frame.next = gip;
                                                                                
  /* Make it the top invoke frame */
  gip = &frame;
                                                                                
  /* Perform the memcpy */
  __asm__ __volatile__ ("nop\nnop");
  __asm__ __volatile__ (
                        "movl $1f, %2\n"
                        "rep; movsl\n"
                        "movl $2, %0\n"
                        "movl %%edx, %%ecx\n"
                        "rep; movsb\n"
                        "1:\n"
                        "movl %%ecx, %1\n"
                        : "=m" (frame.cpinvoke), "=&a" (ret), "=m" (frame.esi)
                        : "D" (to),
                          "S" (from),
                          "c" (count / 4),
                          "d" (count & 0x3));
                                                                                
  /* Unlink the last invoke frame */
  gip = frame.next;
  return ret;
}
#endif
#endif

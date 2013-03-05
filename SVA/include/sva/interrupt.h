/*===- interrupt.h - SVA Interrupts   -------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This header files defines functions and macros used by the SVA Execution
 * Engine for handling interrupts.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef _SVA_INTERRUPT_H
#define _SVA_INTERRUPT_H

#if 0
#include <sva/config.h>
#include <sva/exceptions.h>
#endif
#include <sva/state.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void * sva_getCPUState (tss_t * tssp);

void sva_icontext_setretval (unsigned long, unsigned long, unsigned char error);
void sva_icontext_restart (unsigned long, unsigned long);

/* Types for handlers */
typedef void (*genfault_handler_t)(sva_icontext_t * icontext);
typedef void (*memfault_handler_t)(sva_icontext_t * icontext, void * mp);
typedef void (*interrupt_handler_t)(unsigned int num, sva_icontext_t * icontext);
typedef void * syscall_t;

/* Prototypes for Execution Engine Functions */
extern unsigned char
sva_register_general_exception (unsigned char, genfault_handler_t);

extern unsigned char
sva_register_memory_exception (unsigned char, memfault_handler_t);

extern unsigned char
sva_register_interrupt (unsigned char, interrupt_handler_t);

extern unsigned char
sva_register_syscall (unsigned char, syscall_t);

#if 0
extern void sva_register_old_interrupt (int number, void *interrupt);
extern void sva_register_old_trap      (int number, void *interrupt);
#endif

/**************************** Inline Functions *******************************/

/*
 * Intrinsic: sva_load_lif()
 *
 * Description:
 *  Enables or disables local processor interrupts, depending upon the flag.
 *
 * Inputs:
 *  0  - Disable local processor interrupts
 *  ~0 - Enable local processor interrupts
 */
static inline void
sva_load_lif (unsigned int enable)
{
  if (enable)
    __asm__ __volatile__ ("sti":::"memory");
  else
    __asm__ __volatile__ ("cli":::"memory");
}
                                                                                
/*
 * Intrinsic: sva_save_lif()
 *
 * Description:
 *  Return whether interrupts are currently enabled or disabled on the
 *  local processor.
 */
static inline unsigned int
sva_save_lif (void)
{
  unsigned int eflags;

  /*
   * Get the entire eflags register and then mask out the interrupt enable
   * flag.
   */
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));
  return (eflags & 0x00000200);
}

#if 0
static inline unsigned int
sva_icontext_lif (void * icontextp)
{
  sva_icontext_t * p = (sva_icontext_t *)icontextp;
  return (p->eflags & 0x00000200);
}
#endif

/*
 * Intrinsic: sva_nop()
 *
 * Description:
 *  Provides a volatile operation that does nothing.  This is useful if you
 *  want to wait for an interrupt but don't want to actually do anything.  In
 *  such a case, you need a "filler" instruction that can be interrupted.
 *
 * TODO:
 *  Currently, we're going to use this as an optimization barrier.  Do not move
 *  loads and stores around this.  This is okay, since LLVM will enforce the
 *  same restriction on the LLVM level.
 */
static inline void
sva_nop (void)
{
  __asm__ __volatile__ ("nop" ::: "memory");
}

#ifdef __cplusplus
}
#endif

#endif

/*===- interrupt.c - SVA Execution Engine  --------------------------------===
 * 
 *                     The LLVM Compiler Infrastructure
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file implements the SVA instructions for registering interrupt and
 * exception handlers.
 *
 *===----------------------------------------------------------------------===
 */

#include "sva/config.h"
#include "sva/interrupt.h"
#include "sva/state.h"

/*
 * Default LLVA interrupt, exception, and system call handlers.
 */
void
default_interrupt (unsigned int number, void * state)
{
  return;
}

/*
 * Structure: interrupt_table
 *
 * Description:
 *  This is a table that contains the list of interrupt functions registered
 *  with the Execution Engine.  Whenever an interrupt occurs, one of these
 *  functions will be dispatched.
 */
static void * interrupt_table[256];

/*
 * Structure: userContexts
 *
 * Description:
 *  This struture contains the interrupt contexts of user-space applications.
 *  We are guaranteed to only enter user-space to kernel-space once per
 *  processor, so all of these interrupt icontexts will be stored in SVA memory
 *  here.
 *
 *  Kernel-space interrupt contexts will be stored on the kernel stack.
 */
static sva_icontext_t userContexts[numProcessors];

/*
 * Intrinsic: sva_get_uicontext()
 *
 * Description:
 *  Return a pointer to the user interrupt context for this processor.
 *
 * Notes:
 *  This intrinsic is only here to bootstrap the implementation of SVA.  Once
 *  the SVA interrupt handling code is working properly, this intrinsic should
 *  be removed.
 */
void *
sva_get_uicontext (void) {
  static int index=0;
#if 0
  return &(userContexts[getProcessorID()]);
#else
  return &(userContexts[index++]);
#endif
}

#if 0
/*
 * Intrinsic: sva_register_general_exception()
 *
 * Description:
 *  Register a fault handler with the Execution Engine.  The handlers for these
 *  interrupts do not take any arguments.
 *
 * Return value:
 *  0 - No error
 *  1 - Some error occurred.
 */
unsigned char
sva_register_general_exception (unsigned int number,
                                 genfault_handler_t handler)
{
  /*
   * First, ensure that the exception number is within range.
   */
  if (number > 31)
  {
    __asm__ __volatile__ ("int %0\n" :: "i" (sva_exception_exception));
    return 1;
  }

  /*
   * Ensure that this is not one of the special handlers.
   */
  switch (number)
  {
    case 8:
    case 10:
    case 11:
    case 12:
    case 14:
    case 17:
      __asm__ __volatile__ ("int %0\n" :: "i" (sva_exception_exception));
      return 1;
      break;
    default:
      break;
  }

  /*
   * Put the handler into our dispatch table.
   */
  interrupt_table[number] = handler;
  return 0;
}

/*
 * Intrinsic: sva_register_memory_exception()
 *
 * Description:
 *  Register a fault with the Execution Engine.  This fault handler will need
 *  the memory address that was used by the instruction when the fault occurred.
 */
unsigned char
sva_register_memory_exception (unsigned int number, memfault_handler_t handler)
{
  /*
   * Ensure that this is not one of the special handlers.
   */
  switch (number)
  {
    case 14:
    case 17:
      /*
       * Put the interrupt handler into our dispatch table.
       */
      interrupt_table[number] = handler;
      return 0;
    default:
      __asm__ __volatile__ ("int %0\n" :: "i" (sva_exception_exception));
      return 1;
  }

  return 0;
}

/*
 * Intrinsic: sva_register_interrupt ()
 *
 * Description:
 *  This intrinsic registers an interrupt handler with the Execution Engine.
 */
unsigned char
sva_register_interrupt (unsigned int number, interrupt_handler_t interrupt)
{
  /*
   * Ensure that the number is within range.
   */
  if ((number < 32) || (number > 255))
  {
    __asm__ __volatile__ ("int %0\n" :: "i" (sva_interrupt_exception));
    return 1;
  }

  /*
   * Put the handler into the system call table.
   */
  interrupt_table[number] = interrupt;
  return 0;
}

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
void
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
unsigned int
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

unsigned int
sva_icontext_lif (void * icontextp)
{
  sva_icontext_t * p = icontextp;
  return (p->eflags & 0x00000200);
}

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
void
sva_nop (void)
{
  __asm__ __volatile__ ("nop" ::: "memory");
}

void
sva_nop1 (void)
{
  __asm__ __volatile__ ("nop" ::: "memory");
}
#endif

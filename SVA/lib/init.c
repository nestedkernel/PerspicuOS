/*===- init.c - SVA Execution Engine  ---------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This is code to initialize the SVA Execution Engine.  It is inherited from
 * the original SVA system.
 *
 *===----------------------------------------------------------------------===
 */

/*-
 * Copyright (c) 1989, 1990 William F. Jolitz
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *  from: @(#)segments.h  7.1 (Berkeley) 5/9/91
 * $FreeBSD: release/9.0.0/sys/amd64/include/segments.h 227946 2011-11-24 18:44:14Z rstone $
 */

/*-
 * Copyright (c) 2003 Peter Wemm.
 * Copyright (c) 1993 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: release/9.0.0/sys/amd64/include/cpufunc.h 223796 2011-07-05 18:42:10Z jkim $
 */

#include "sva/config.h"

#include <string.h>
#include <limits.h>

#include <sys/types.h>

extern int printf(const char *, ...);

#if 0
void register_x86_interrupt (int number, void *interrupt, unsigned char priv);
void register_x86_trap (int number, void *trap);
static void fptrap (void);
#endif
static void init_idt (void);
#if 0
static void init_debug (void);
static void init_mmu (void);
static void init_fpu ();
static int init_dispatcher ();
#endif

/* Flags whether the FPU has been used */
unsigned char llva_fp_used = 0;

/* Default LLVA interrupt, exception, and system call handlers */
extern void default_interrupt (unsigned int number, void * icontext);

/* Map logical processor ID to an array in the SVA data structures */
unsigned int svaProcMap[numProcessors] = {[0 ... numProcessors - 1] = UINT_MAX};

/*
 * Structure: interrupt_table
 *
 * Description:
 *  This is a table that contains the list of interrupt functions registered
 *  with the Execution Engine.  Whenever an interrupt occurs, one of these
 *  functions will be dispatched.
 *
 *  Note that we need one of these per processor.
 */
void * interrupt_table[256][numProcessors];

/*
 * Structure: sva_idt
 *
 * Description:
 *  This is the x86 interrupt descriptor table.  We use it to hold all of the
 *  interrupt vectors internally within the Execution Engine.
 *
 *  Note that we need one of these per processor.
 */
static unsigned long sva_idt[2*256][numProcessors];

#if 0
/*
 * Function: register_x86_interrupt()
 *
 * Description:
 *  Install the specified handler into the x86 Interrupt Descriptor Table (IDT)
 *  as an interrupt.
 *
 * Inputs:
 *  number    - The interrupt number.
 *  interrupt - A pointer to the interrupt handler.
 *  priv      - The i386 privilege level which can access this interrupt.
 */
void
register_x86_interrupt (int number, void *interrupt, unsigned char priv)
{
  /* The two words for an individiual interrupt entry */
  unsigned int v1;
  unsigned int v2;

  /*
   * Install the new system call handler.
   */
  v1 = 0x00100000 | ((unsigned)interrupt & 0x0000ffff);
  v2 = ((unsigned)interrupt & 0xffff0000) | (0x8E00) | (priv << 13);
  sva_idt[number*2]   = v1;
  sva_idt[number*2+1] = v2;
}

/*
 * Function: register_x86_trap()
 *
 * Description:
 *  Install the specified handler in the x86 Interrupt Descriptor Table (IDT)
 *  as a trap handler that can be called from privilege levels 0-3.
 *
 * Inputs:
 *  number  - The interrupt number.
 *  trap - A function pointer to the system call handler.
 */
void
register_x86_trap (int number, void *trap)
{
  /* The two words for an individiual interrupt entry */
  unsigned int v1;
  unsigned int v2;

  /*
   * Install the new system call handler.
   *  v1: Segment selector 0x10 (kernel) + lower 16 bits of handler
   *  v2: Upper 16 bits of handler + flags
   */
  v1 = 0x00100000 | ((unsigned)trap & 0x0000ffff);
  v2 = ((unsigned)trap & 0xffff0000) | (0xEF00);
  sva_idt[number*2]   = v1;
  sva_idt[number*2+1] = v2;
}

/*
 * Function: fptrap()
 *
 * Description:
 *  Function that captures FP traps and flags use of the FP unit accordingly.
 */
static void
fptrap (void)
{
  const int ts = 0x00000008;
  int cr0;

  /*
   * Flag that the floating point unit has now been used.
   */
  llva_fp_used = 1;

  /*
   * Turn off the TS bit in CR0; this allows the FPU to proceed with floating
   * point operations.
   */
  __asm__ __volatile__ ("mov %%cr0, %0\n"
                        "andl  %1,  %0\n"
                        "mov %0, %%cr0\n" : "=&r" (cr0) : "r" (~(ts)));
}
#endif

/*
 * Function: init_idt()
 *
 * Description:
 *  Initialize the x86 Interrupt Descriptor Table (IDT) to some nice default
 *  values.
 *
 * TODO:
 *  Currently, this function will take over the IDT from the OS kernel.  It
 *  will copy the current IDT to its own memory and then configure the IDT to
 *  use the internal SVA table.
 *
 *  Once the port is done, SVA should set up the entire IDT table itself.
 */
static void
init_idt (void) {
  /* Argument to lidt/sidt taken from FreeBSD. */
  struct region_descriptor {
    unsigned long rd_limit:16;    /* segment extent */
    unsigned long rd_base :64 __attribute__ ((packed));  /* base address  */
  } __attribute__ ((packed)) sva_idtreg;

#if 0
  /*
   * Set up the table in memory.  Each entry will be an interrupt gate to
   * a dummy function.
   */
  for (int index = 0; index < 256; index++)
  {
    interrupt_table[index] =  default_interrupt;
  }
#endif

  /*
   * Find the current interrupt descriptor table (IDT).
   */
  __asm__ __volatile__ ("sidt %0": "=m" (sva_idtreg));

  printf ("SVA: %x: %x %lx\n", getProcessorID(),
                               sva_idtreg.rd_limit,
                               sva_idtreg.rd_base);

#if 0
  /*
   * Copy the contents of the old IDT into the SVA IDT.
   */
  unsigned short copySize = sva_idtreg.rd_limit + 1;
  memcpy (&(sva_idt[0][getProcessorID()]),
          (unsigned char *) sva_idtreg.rd_base,
          copySize);
#endif

  /*
   * Load our descriptor table on to the processor.
   */
#if 0
  sva_idtreg.rd_limit = sizeof (&(sva_idt[0][getProcessorID()]));
  sva_idtreg.rd_base = (uintptr_t) sva_idt;
  __asm__ __volatile__ ("lidt (%0)" : : "r" (&sva_idtreg));
#endif
  return;
}

#if 0
static void
init_debug (void)
{
  __asm__ ("movl $0, %eax\n"
           "movl %eax, %db0\n"
           "movl %eax, %db1\n"
           "movl %eax, %db2\n"
           "movl %eax, %db3\n"
           "movl %eax, %db6\n"
           "movl %eax, %db7\n");
  return;
}

/*
 * Functoin: init_mmu()
 *
 * Description:
 *  Initialize the i386 MMU.
 */
static void
init_mmu (void)
{
  const int pse   = (1 << 4);
  const int pge   = (1 << 7);
  const int tsd   = (1 << 2);
  const int pvi   = (1 << 1);
  const int de    = (1 << 3);
  const int pce   = (1 << 8);
  const int osfxr = ((1 << 9) | (1 << 10));
  int value;

  /*
   * Enable:
   *  PSE: Page Size Extension (i.e. large pages).
   *  PGE: Page Global Extension (i.e. global pages).
   *
   * Disable:
   *  TSD: Allow user mode applications to read the timestamp counter.
   *  PVI: Virtual Interrupt Flag in Protected Mode.
   *   DE: By disabling, allows for legacy debug register support for i386.
   *
   * We will assume that page size extensions and page global bit extensions
   * exist within the processor.  If they don't, you're in big trouble!
   */
  __asm__ __volatile__ ("mov %%cr4, %0\n"
                        "orl  %1, %0\n"
                        "andl %2, %0\n"
                        "mov %0, %%cr4\n"
                        : "=&r" (value)
                        : "r" (osfxr | pse | pge | pce),
                          "r" (~(pvi | de | tsd)));

  return;
}

/*
 * Function: init_fpu()
 *
 * Description:
 *  Initialize various things that needs to be initialized for the FPU.
 */
static void
init_fpu ()
{
  const int mp = 0x00000002;
  const int em = 0x00000004;
  const int ts = 0x00000008;
  int cr0;

  /*
   * Configure the processor so that the first use of the FPU generates an
   * exception.
   */
  __asm__ __volatile__ ("mov %%cr0, %0\n"
                        "andl  %1, %0\n"
                        "orl   %2, %0\n"
                        "mov %0, %%cr0\n"
                        : "=&r" (cr0)
                        : "r" (~(em)),
                          "r" (mp | ts));

  /*
   * Register the co-processor trap so that we know when an FP operation has
   * been performed.
   */
  llva_register_general_exception (0x7, fptrap);

  /*
   * Flag that the floating point unit has not been used.
   */
  llva_fp_used = 0;
  return;
}
#endif

/*
 * Intrinsic: sva_init()
 *
 * Description:
 *  This routine initializes all of the information needed by the LLVA
 *  Execution Engine.  We do things here like setting up the interrupt
 *  descriptor table.
 */
void
sva_init ()
{
#if 0
  init_segs ();
  init_debug ();
#endif
  init_idt ();
#if 0
  init_dispatcher ();
  init_mmu ();
  init_fpu ();
  llva_reset_counters();
  llva_reset_local_counters();
#endif
}

#define REGISTER_EXCEPTION(number) \
  extern void trap##number(void); \
  register_x86_interrupt ((number),trap##number, 0);

#define REGISTER_INTERRUPT(number) \
  extern void interrupt##number(void); \
  register_x86_interrupt ((number),interrupt##number, 0);

extern void mem_trap14(void);
extern void mem_trap17(void);

#if 0
static int
init_dispatcher ()
{
  /* System Call Trap */
#if 0
  register_x86_interrupt (0x7f, sc_trap,    3);
  register_x86_interrupt (0x80, sc_trap,    3);
#else
  register_x86_trap (0x7f, sc_trap);
  register_x86_trap (0x80, sc_trap);
#endif

  /* Page Fault and Memory Alignment Trap, respectively */
  register_x86_interrupt (0x0e, mem_trap14, 0);
  register_x86_interrupt (0x11, mem_trap17, 0);

  /* Register general exception */
  REGISTER_EXCEPTION(0);
  REGISTER_EXCEPTION(1);
  REGISTER_EXCEPTION(2);
  REGISTER_EXCEPTION(3);
  REGISTER_EXCEPTION(4);
  REGISTER_EXCEPTION(5);
  REGISTER_EXCEPTION(6);
  REGISTER_EXCEPTION(7);
  REGISTER_EXCEPTION(8);
  REGISTER_EXCEPTION(9);
  REGISTER_EXCEPTION(10);
  REGISTER_EXCEPTION(11);
  REGISTER_EXCEPTION(12);
  REGISTER_EXCEPTION(13);
  REGISTER_EXCEPTION(15);
  REGISTER_EXCEPTION(16);
  REGISTER_EXCEPTION(18);
  REGISTER_EXCEPTION(19);
  REGISTER_EXCEPTION(20);
  REGISTER_EXCEPTION(21);
  REGISTER_EXCEPTION(22);
  REGISTER_EXCEPTION(23);
  REGISTER_EXCEPTION(24);
  REGISTER_EXCEPTION(25);
  REGISTER_EXCEPTION(26);
  REGISTER_EXCEPTION(27);
  REGISTER_EXCEPTION(28);
  REGISTER_EXCEPTION(29);
  REGISTER_EXCEPTION(30);
  REGISTER_EXCEPTION(31);

  /* Register re-routed I/O interrupts */
  REGISTER_INTERRUPT(32);
  REGISTER_INTERRUPT(33);
  REGISTER_INTERRUPT(34);
  REGISTER_INTERRUPT(35);
  REGISTER_INTERRUPT(36);
  REGISTER_INTERRUPT(37);
  REGISTER_INTERRUPT(38);
  REGISTER_INTERRUPT(39);
  REGISTER_INTERRUPT(40);
  REGISTER_INTERRUPT(41);
  REGISTER_INTERRUPT(42);
  REGISTER_INTERRUPT(43);
  REGISTER_INTERRUPT(44);
  REGISTER_INTERRUPT(45);
  REGISTER_INTERRUPT(46);
  REGISTER_INTERRUPT(47);
  REGISTER_INTERRUPT(48);

  REGISTER_INTERRUPT(49);
  REGISTER_INTERRUPT(57);
  REGISTER_INTERRUPT(65);
  REGISTER_INTERRUPT(73);
  REGISTER_INTERRUPT(89);
  REGISTER_INTERRUPT(121);
  REGISTER_INTERRUPT(137);
  REGISTER_INTERRUPT(153);
  REGISTER_INTERRUPT(161);

  /* Register SMP interrupts */
  REGISTER_INTERRUPT(239);
  REGISTER_INTERRUPT(251);
  REGISTER_INTERRUPT(252);
  REGISTER_INTERRUPT(253);
  REGISTER_INTERRUPT(254);
  REGISTER_INTERRUPT(255);
  return 0;
}
#endif


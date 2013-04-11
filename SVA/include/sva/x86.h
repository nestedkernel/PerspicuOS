/*===- x86.h - SVA Execution Engine ----------------------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===----------------------------------------------------------------------===
 *
 * This file defines structures used by the x86_64 architecture.
 *
 *===----------------------------------------------------------------------===
 */

#include <sys/types.h>

#ifndef _SVA_X86_H
#define _SVA_X86_H

/*
 * Struction: tss_t
 *
 * Description:
 *  This is an x86_64 Task State Segment.
 */
typedef struct {
  unsigned reserved0 __attribute__((packed));

  /*
   * Pointers to the kernel stack pointer when the interrupt stack table is not
   * used
   */
  uintptr_t rsp0 __attribute__((packed));
  uintptr_t rsp1 __attribute__((packed));
  uintptr_t rsp2 __attribute__((packed));
  uintptr_t reserved1 __attribute__((packed));

  /*
   * Interrupt Stack Table (IST) Pointers: Marks where the kernel stack should
   * be set on interrupt.
   */
  uintptr_t ist1 __attribute__((packed));
  uintptr_t ist2 __attribute__((packed));
  uintptr_t ist3 __attribute__((packed));
  uintptr_t ist4 __attribute__((packed));
  uintptr_t ist5 __attribute__((packed));
  uintptr_t ist6 __attribute__((packed));
  uintptr_t ist7 __attribute__((packed));

  uintptr_t reserved2 __attribute__((packed));
  uintptr_t reserved3 __attribute__((packed));

  /* I/O Permission Map */
  unsigned int iomap __attribute__((packed));
} tss_t;

/* Flags bits in x86_64 PTE entries */
static const unsigned PTE_PRESENT  = 0x0001u;
static const unsigned PTE_CANWRITE = 0x0002u;
static const unsigned PTE_CANUSER  = 0x0004u;
static const unsigned PTE_PS       = 0x0080u;
#endif

/*===- mmu.h - SVA Execution Engine  =-------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 */

#ifndef MMU_H
#define MMU_H

/*
 *****************************************************************************
 * Define structures used in the SVA MMU interface.
 *****************************************************************************
 */
typedef unsigned long pte_t ;
typedef unsigned long pde_t;
typedef unsigned long pdp_t;
typedef unsigned long pme_t;

/*
 * Function: sva_mm_save_pgtable()
 *
 * Description:
 *  Get the current page table.
 */
static inline void *
sva_mm_save_pgtable (void)
{
  void * p;
  __asm__ __volatile__ ("movq %%cr3, %0\n" : "=r" (p));
  return p;
}

#endif


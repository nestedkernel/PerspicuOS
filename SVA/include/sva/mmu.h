/*===- mmu.h - SVA Execution Engine  =-------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 */

#ifndef SVA_MMU_H
#define SVA_MMU_H

#include <sys/types.h>

/* Size of the smallest page frame in bytes */
static const uintptr_t X86_PAGE_SIZE = 4096u;

/*
 *****************************************************************************
 * Define structures used in the SVA MMU interface.
 *****************************************************************************
 */
typedef uintptr_t cr3_t;
typedef uintptr_t pml4e_t;
typedef uintptr_t pdpte_t;
typedef uintptr_t pde_t;
typedef uintptr_t pte_t;

extern uintptr_t getPhysicalAddr (void * v);
extern pml4e_t * mapSecurePage (unsigned char * v, uintptr_t paddr);
extern void unmapSecurePage (unsigned char * v);

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

/*
 * Function: sva_mm_load_pgtable()
 *
 * Description:
 *  Set the current page table.  This implementation will also enable paging.
 *
 * TODO:
 *  This should check that the page table points to an L1 page frame.
 */
static inline void
sva_mm_load_pgtable (void * pg)
{
  unsigned int cr0;
  __asm__ __volatile__ ("movq %1, %%cr3\n"
                        "movl %%cr0, %0\n"
                        "orl  $0x80000000, %0\n"
                        "movl %0, %%cr0\n"
                        : "=r" (cr0)
                        : "r" (pg) : "memory");
  return;
}

static inline void
sva_mm_flush_tlb (void * address) {
  __asm__ __volatile__ ("invlpg %0" : : "m" (address) : "memory");
  return;
}

#endif


/*===- mmu_intrinsics.h - SVA Execution Engine  =------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *
 *===----------------------------------------------------------------------===
 *
 *       Filename:  mmu_intrinsics.h
 *
 *    Description:  This file exports the sva instrinsics available for
 *                  manipulating page tables. The key reason to have this in
 *                  addition to the mmu.h is that the mmu.h code is primarily
 *                  internal SVA functionality for the mmu management and
 *                  should not be exported. 
 *
 *        Version:  1.0
 *        Created:  04/24/13 04:31:31
 *       Revision:  none
 *
 *===----------------------------------------------------------------------===
 */

#ifndef SVA_MMU_INTRINSICS_H
#define SVA_MMU_INTRINSICS_H

#include "mmu_types.h"

/*
 *****************************************************************************
 * SVA intrinsics implemented in the library
 *****************************************************************************
 */
extern void sva_mm_load_pgtable (void * pg);
extern void sva_load_cr0 (unsigned long val);
extern void sva_declare_leaf_page (unsigned long frameAddr, pte_t *pte);
extern void sva_declare_l1_page (unsigned long frame, uintptr_t vaddr);
extern void sva_declare_l2_page (unsigned long frame, uintptr_t vaddr);
extern void sva_declare_l3_page (unsigned long frame, uintptr_t vaddr);
extern void sva_declare_l4_page (unsigned long frame, uintptr_t vaddr);
extern void sva_update_mapping (page_entry_t * ptePtr, page_entry_t val);
extern void sva_update_l1_mapping (pte_t * ptePtr, page_entry_t val);
extern void sva_update_l2_mapping (pde_t * pdePtr, page_entry_t val);
extern void sva_update_l3_mapping (pdpte_t * pdptePtr, page_entry_t val);
extern void sva_update_l4_mapping (pml4e_t * pml4ePtr, page_entry_t val);
extern void sva_remove_mapping (page_entry_t * ptePtr);
extern void sva_mmu_init(pml4e_t * kpml4Mapping, unsigned long nkpml4e, uintptr_t
        btext, uintptr_t etext);

/* Key initialization and secure storage allocation */
extern void sva_translate();

/*
 *****************************************************************************
 * SVA intrinsics implemented as inline functions
 *****************************************************************************
 */

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

static inline void
sva_mm_flush_tlb (void * address) {
  __asm__ __volatile__ ("invlpg %0" : : "m" (address) : "memory");
  return;
}

#endif /* SVA_MMU_INTRINSICS_H */

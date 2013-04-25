/*===- mmu_types.h - SVA Execution Engine  =------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *
 *===----------------------------------------------------------------------===
 *
 *       Filename:  mmu_types.h
 *
 *    Description:  This file defines shared data types that are in both mmu.h
 *                  and mmu_intrinsics.h. 
 *
 *        Version:  1.0
 *        Created:  04/24/13 05:58:42
 *       Revision:  none
 *
 *===----------------------------------------------------------------------===
 */

#ifndef SVA_MMU_TYPES_H
#define SVA_MMU_TYPES_H

#include <sys/types.h>

typedef uintptr_t cr3_t;
typedef uintptr_t pml4e_t;
typedef uintptr_t pdpte_t;
typedef uintptr_t pde_t;
typedef uintptr_t pte_t;
typedef uintptr_t page_entry_t;

#endif /* SVA_MMU_TYPES_H */

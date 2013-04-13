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

/* Start and end addresses of the secure memory */
#define SECMEMSTART 0xffffff0000000000u
#define SECMEMEND   0xffffff8000000000u

//----------------------------------------------------------------------------
/*
 * ===========================================================================
 * BEGIN FreeBSD CODE BLOCK
 * ===========================================================================
 */

/* MMU Flags ---- Intel Nomenclature ---- */
/*TODO FIXME John I include freebsd defines here... bad?*/
#define PG_V        0x001   /* P    Valid           */
#define PG_RW       0x002   /* R/W  Read/Write      */
#define PG_U        0x004   /* U/S  User/Supervisor     */
#define PG_NC_PWT   0x008   /* PWT  Write through       */
#define PG_NC_PCD   0x010   /* PCD  Cache disable       */
#define PG_A        0x020   /* A    Accessed        */
#define PG_M        0x040   /* D    Dirty           */
#define PG_PS       0x080   /* PS   Page size (0=4k,1=2M)   */
#define PG_PTE_PAT  0x080   /* PAT  PAT index       */
#define PG_G        0x100   /* G    Global          */
#define PG_AVAIL1   0x200   /*    / Available for system    */
#define PG_AVAIL2   0x400   /*   <  programmers use     */
#define PG_AVAIL3   0x800   /*    \             */
#define PG_PDE_PAT  0x1000  /* PAT  PAT index       */
#define PG_NX       (1ul<<63) /* No-execute */

/* Our various interpretations of the above */
#define PG_W        PG_AVAIL1   /* "Wired" pseudoflag */
#define PG_MANAGED  PG_AVAIL2
#define PG_FRAME    (0x000ffffffffff000ul)
#define PG_PS_FRAME (0x000fffffffe00000ul)
#define PG_PROT     (PG_RW|PG_U)    /* all protection bits . */
#define PG_N        (PG_NC_PWT|PG_NC_PCD)   /* Non-cacheable */

/*
 * ===========================================================================
 * END FreeBSD CODE BLOCK
 * ===========================================================================
 */
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------

/*
 *****************************************************************************
 * Define structures used in the SVA MMU interface.
 *****************************************************************************
 */
typedef uintptr_t cr3_t;
typedef uintptr_t pml4e_t;
typedef uintptr_t pdpe_t;
typedef uintptr_t pde_t;
typedef uintptr_t pte_t;

extern uintptr_t getPhysicalAddr (void * v);
extern pml4e_t * mapSecurePage (unsigned char * v, uintptr_t paddr);
extern void unmapSecurePage (unsigned char * v);

/*
 *****************************************************************************
 * SVA intrinsics implemented in the library
 *****************************************************************************
 */
extern void sva_mm_load_pgtable (void * pg);
extern void sva_declare_l1_page (unsigned long frame, pde_t *pde);

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

#endif


/*===- mmu.h - SVA Execution Engine  =-------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * Copyright (c) 2003 Peter Wemm.
 * Copyright (c) 1991 Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department and William Jolitz of UUNET Technologies Inc.
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
 * Derived from hp300 version by Mike Hibler, this version by William
 * Jolitz uses a recursive map [a pde points to the page directory] to
 * map the page tables using the pagetables themselves. This is done to
 * reduce the impact on kernel virtual memory for lots of sparse address
 * space, and to reduce the cost of memory to each process.
 *
 *  from: hp300: @(#)pmap.h 7.2 (Berkeley) 12/16/90
 *  from: @(#)pmap.h    7.4 (Berkeley) 5/12/91
 * $FreeBSD: release/9.0.0/sys/amd64/include/pmap.h 222813 2011-06-07 08:46:13Z attilio $
 *
 *===----------------------------------------------------------------------===
 */


#ifndef SVA_MMU_H
#define SVA_MMU_H

#include <sys/types.h>
#include "mmu_types.h"

/* Size of the smallest page frame in bytes */
static const uintptr_t X86_PAGE_SIZE = 4096u;

/* Number of bits to shift to get the page number out of a PTE entry */
static const unsigned PAGESHIFT = 12;

/* Size of the physical memory and page size in bytes */
static const unsigned long memSize = 0x0000000800000000u;
static const unsigned long pageSize = 4096;
static const unsigned long numPageDescEntries = memSize / pageSize;

/* Start and end addresses of the secure memory */
#define SECMEMSTART 0xffffff0000000000u
#define SECMEMEND   0xffffff8000000000u

/* Start and end addresses of user memory */
static const uintptr_t USERSTART = 0x0000000000000000u;
static const uintptr_t USEREND = 0x00007fffffffffffu;

/* Mask to get the proper number of bits from the virtual address */
static const uintptr_t vmask = 0x0000000000000ff8u;

/* The number of references allowed per page table page */
static const int maxPTPVARefs = 1;

/* The count must be at least this value to remove a mapping to a page */
static const int minRefCountToRemoveMapping = 1;

/*
 * Offset into the PML4E at which the mapping for the secure memory region can
 * be found.
 */
static const uintptr_t secmemOffset = ((SECMEMSTART >> 39) << 3) & vmask;

/* Zero mapping is the mapping that eliminates the previous entry */
static const uintptr_t ZERO_MAPPING = 0;

/*
 * Assert macro for SVA
 */
/* 
 * TODO: this will be removed. It is only used for temporarily obtaining
 * performance numbers.
 */
static inline void
SVA_NOOP_ASSERT (int res, char * st) {
  if (!res) res++;
}

/*
 * Function: SVA_ASSERT()
 *
 * Description:
 *  Check that the test (given as the first argument) passed.  If it did not,
 *  then panic with the specified string.
 */
static inline void
SVA_ASSERT (unsigned char passed, char * str) {
  if (!passed)
    panic ("%s", str);
  return;
}

/*
 *****************************************************************************
 * Define structures used in the SVA MMU interface.
 *****************************************************************************
 */

/*
 * Frame usage constants
 */
/* Enum representing the four page types */
enum page_type_t {
    PG_UNUSED = 0,
    PG_L1,          /*  1: Defines a page being used as an L1 PTP */
    PG_L2,          /*  2: Defines a page being used as an L2 PTP */
    PG_L3,          /*  3: Defines a page being used as an L3 PTP */
    PG_L4,          /*  4: Defines a page being used as an L4 PTP */
    PG_LEAF,        /*  5: Generic type representing a valid LEAF page */
    PG_TKDATA,      /*  6: Defines a kernel data page */
    PG_TUDATA,      /*  7: Defines a user data page */
    PG_CODE,        /*  8: Defines a code page */
    PG_SVA,         /*  9: Defines an SVA system page */
    PG_GHOST,       /* 10: Defines a secure page */
    PG_DML1,        /* 11: Defines a L1 PTP  for the direct map */
    PG_DML2,        /* 12: Defines a L2 PTP  for the direct map */
    PG_DML3,        /* 13: Defines a L3 PTP  for the direct map */
    PG_DML4,        /* 14: Defines a L4 PTP  for the direct map */
};

/* Mask to get the address bits out of a PTE, PDE, etc. */
static const uintptr_t addrmask = 0x000ffffffffff000u;

/*
 * Struct: page_desc_t
 *
 * Description:
 *  There is one element of this structure for each physical page of memory
 *  in the system.  It records information about the physical memory (and the
 *  data stored within it) that SVA needs to perform its MMU safety checks.
 */
typedef struct page_desc_t {
    /* Type of frame */
    enum page_type_t type;

    /*
     * If the page is a page table page, mark the virtual addres to which it is
     * mapped.
     */
    uintptr_t pgVaddr;

    /* Flag to denote whether the page is a Ghost page table page */
    unsigned ghostPTP : 1;

    /* Flag denoting whether or not this frame is a stack frame */
    unsigned stack : 1;
    
    /* Flag denoting whether or not this frame is a code frame */
    unsigned code : 1;
    
    /* State of page: value of != 0 is active and 0 is inactive */
    unsigned active : 1;

    /* Number of times a page is mapped */
    unsigned count : 12;

    /* Is this page a user page? */
    unsigned user : 1;
} page_desc_t;

/* Array describing the physical pages */
/* The index is the physical page number */
static page_desc_t page_desc[numPageDescEntries];

/*
 * ===========================================================================
 * BEGIN FreeBSD CODE BLOCK
 *
 * $FreeBSD: release/9.0.0/sys/amd64/include/pmap.h 222813 2011-06-07 08:46:13Z attilio $
 * ===========================================================================
 */

/* MMU Flags ---- Intel Nomenclature ---- */
#define PG_V        0x001   /* P    Valid               */
#define PG_RW       0x002   /* R/W  Read/Write          */
#define PG_U        0x004   /* U/S  User/Supervisor     */
#define PG_NC_PWT   0x008   /* PWT  Write through       */
#define PG_NC_PCD   0x010   /* PCD  Cache disable       */
#define PG_A        0x020   /* A    Accessed            */
#define PG_M        0x040   /* D    Dirty               */
#define PG_PS       0x080   /* PS   Page size (0=4k,1=2M)   */
#define PG_PTE_PAT  0x080   /* PAT  PAT index           */
#define PG_G        0x100   /* G    Global              */
#define PG_AVAIL1   0x200   /*    / Available for system    */
#define PG_AVAIL2   0x400   /*   <  programmers use     */
#define PG_AVAIL3   0x800   /*    \                     */
#define PG_PDE_PAT  0x1000  /* PAT  PAT index           */
#define PG_NX       (1ul<<63) /* No-execute             */

/* Various interpretations of the above */
#define PG_W        PG_AVAIL1   /* "Wired" pseudoflag */
#define PG_MANAGED  PG_AVAIL2
#define PG_FRAME    (0x000ffffffffff000ul)
#define PG_PS_FRAME (0x000fffffffe00000ul)
#define PG_PROT     (PG_RW|PG_U)    /* all protection bits . */
#define PG_N        (PG_NC_PWT|PG_NC_PCD)   /* Non-cacheable */

/* Size of the level 1 page table units */
#define PAGE_SHIFT  12      /* LOG2(PAGE_SIZE) */
#define PAGE_SIZE   (1<<PAGE_SHIFT) /* bytes/page */
#define NPTEPG      (PAGE_SIZE/(sizeof (pte_t)))
#define NPTEPGSHIFT 9       /* LOG2(NPTEPG) */
#define PAGE_MASK   (PAGE_SIZE-1)
/* Size of the level 2 page directory units */
#define NPDEPG      (PAGE_SIZE/(sizeof (pde_t)))
#define NPDEPGSHIFT 9       /* LOG2(NPDEPG) */
#define PDRSHIFT    21              /* LOG2(NBPDR) */
#define NBPDR       (1<<PDRSHIFT)   /* bytes/page dir */
#define PDRMASK     (NBPDR-1)
/* Size of the level 3 page directory pointer table units */
#define NPDPEPG     (PAGE_SIZE/(sizeof (pdpte_t)))
#define NPDPEPGSHIFT    9       /* LOG2(NPDPEPG) */
#define PDPSHIFT    30      /* LOG2(NBPDP) */
#define NBPDP       (1<<PDPSHIFT)   /* bytes/page dir ptr table */
#define PDPMASK     (NBPDP-1)
/* Size of the level 4 page-map level-4 table units */
#define NPML4EPG    (PAGE_SIZE/(sizeof (pml4e_t)))
#define NPML4EPGSHIFT   9       /* LOG2(NPML4EPG) */
#define PML4SHIFT   39      /* LOG2(NBPML4) */
#define NBPML4      (1UL<<PML4SHIFT)/* bytes/page map lev4 table */
#define PML4MASK    (NBPML4-1)

/*
 * ===========================================================================
 * END FreeBSD CODE BLOCK
 * ===========================================================================
 */

extern uintptr_t getPhysicalAddr (void * v);
extern pml4e_t mapSecurePage (uintptr_t v, uintptr_t paddr);
extern void unmapSecurePage (unsigned char * cr3, unsigned char * v);

/*
 *****************************************************************************
 * SVA Implementation Function Prototypes
 *****************************************************************************
 */
void init_mmu(void);
void init_leaf_page_from_mapping(page_entry_t mapping);

/*
 *****************************************************************************
 * SVA utility functions needed by multiple compilation units
 *****************************************************************************
 */

/* CR0 Flags */
#define     CR0_WP      0x00010000      /* Write protect enable */

/*
 * Function: getVirtual()
 *
 * Description:
 *  This function takes a physical address and converts it into a virtual
 *  address that the SVA VM can access.
 *
 *  In a real system, this is done by having the SVA VM create its own
 *  virtual-to-physical mapping of all of physical memory within its own
 *  reserved portion of the virtual address space.  However, for now, we'll
 *  take advantage of FreeBSD's direct map of physical memory so that we don't
 *  have to set one up.
 */
static inline unsigned char *
getVirtual (uintptr_t physical) {
  return (unsigned char *)(physical | 0xfffffe0000000000u);
}

/*
 * Function: get_pagetable()
 *
 * Description:
 *  Return a physical address that can be used to access the current page table.
 */
static inline unsigned char *
get_pagetable (void) {
  /* Value of the CR3 register */
  uintptr_t cr3;

  /* Get the page table value out of CR3 */
  __asm__ __volatile__ ("movq %%cr3, %0\n" : "=r" (cr3));

  /*
   * Shift the value over 12 bits.  The lower-order 12 bits of the page table
   * pointer are assumed to be zero, and so they are reserved or used by the
   * hardware.
   */
  return (unsigned char *)((((uintptr_t)cr3) & 0x000ffffffffff000u));
}

/*
 *****************************************************************************
 * Low level register read/write functions
 *****************************************************************************
 */
#define MSR_REG_EFER    0xC0000080      /* MSR for EFER register */

static inline uint64_t
rdmsr(u_int msr)
{
    uint32_t low, high;

    __asm __volatile("rdmsr" : "=a" (low), "=d" (high) : "c" (msr));
    return (low | ((uint64_t)high << 32));
}

/* 
 * Return the current value in cr0
 */
static void
_load_cr0(unsigned long val) {
    __asm __volatile("movq %0,%%cr0" : : "r" (val));
}

/*
 * Function: load_cr3
 *
 * Description: 
 *  Load the cr3 with the given value passed in.
 */
static inline void load_cr3(unsigned long data)
{ 
    __asm __volatile("movq %0,%%cr3" : : "r" (data) : "memory"); 
}


static inline u_long
_rcr0(void) {
    u_long  data;
    __asm __volatile("movq %%cr0,%0" : "=r" (data));
    return (data);
}

static inline u_long
_rcr3(void) {
    u_long  data;
    __asm __volatile("movq %%cr3,%0" : "=r" (data));
    return (data);
}

static inline u_long
_rcr4(void) {
    u_long  data;
    __asm __volatile("movq %%cr4,%0" : "=r" (data));
    return (data);
}

static inline uint64_t
_efer(void) {
    return rdmsr(MSR_REG_EFER);
}

static inline void
print_regs(void) {
    printf("Printing Active Reg Values:\n");
    printf("\tEFER: %p\n", _efer());
    printf("\t CR0: %p\n", _rcr0());
    printf("\t CR3: %p\n", _rcr3());
    printf("\t CR4: %p\n", _rcr4());
}

/*
 *****************************************************************************
 * MMU declare, update, and verification helper routines
 *****************************************************************************
 */
/*
 * Description:
 *  Given a page table entry value, return the page description associate with
 *  the frame being addressed in the mapping.
 *
 * Inputs:
 *  mapping: the mapping with the physical address of the referenced frame
 *
 * Return:
 *  Pointer to the page_desc for this frame
 */
page_desc_t * getPageDescPtr(unsigned long mapping);

/* See implementation in c file for details */
static inline page_entry_t * va_to_pte (uintptr_t va, enum page_type_t level);
static inline int isValidMappingOrder (page_desc_t *pgDesc, uintptr_t newVA);

#if 0
static inline uintptr_t
pageVA(page_desc_t pg){
    return getVirtual(pg.physAddress);    
}
#endif

/*
 * Description:
 *  This function takes a page table mapping and set's the flag to read only. 
 * 
 * Inputs:
 *  - mapping: the mapping to add read only flag to
 *
 * Return:
 *  - A new mapping set to read only
 *
 *  Note that setting the read only flag does not necessarily mean that the
 *  read only protection is enabled in the system. It just indicates that if
 *  the system has the write protection enabled then the value of this bit is
 *  considered.
 */
static inline page_entry_t
setMappingReadOnly (page_entry_t mapping) { 
  return (mapping & ~((uintptr_t)(PG_RW))); 
}

/*
 * Description:
 *  This function takes a page table mapping and set's the flag to read/write. 
 * 
 * Inputs:
 *  - mapping: the mapping to which to add read/write permission
 *
 * Return:
 *  - A new mapping set with read/write permission
 */
static inline page_entry_t
setMappingReadWrite (page_entry_t mapping) { 
  return (mapping | PG_RW); 
}


/*
 *****************************************************************************
 * Page descriptor query functions
 *****************************************************************************
 */

/* Page setter methods */

/* State whether this kernel virtual address is in the secure memory range */
static inline int isGhostVA(uintptr_t va)
    { return (va >= SECMEMSTART) && (va < SECMEMEND); }

/* 
 * The following functions query the given page descriptor for type attributes.
 */
static inline int isFramePg (page_desc_t *page) { 
  return (page->type == PG_UNUSED)   ||      /* Defines an unused page */
         (page->type == PG_TKDATA)   ||      /* Defines a kernel data page */
         (page->type == PG_TUDATA)   ||      /* Defines a user data page */
         (page->type == PG_CODE);           /* Defines a code page */
}

/* Description: Return whether the page is active or not */
static inline int pgIsActive (page_desc_t *page) 
    { return page->type != PG_UNUSED ; } 

static inline unsigned char isDirectMap (unsigned char * p) {
  uintptr_t address = (uintptr_t)p;
  return ((0xfffffe0000000000u <= address) && (address <= 0xffffff0000000000u));
}

/* The number of active references to the page */
static inline int pgRefCount(page_desc_t *page) { return page->count; }

/* Page type queries */
static inline int isL1Pg (page_desc_t *page) { return page->type == PG_L1; }
static inline int isL2Pg (page_desc_t *page) { return page->type == PG_L2; }
static inline int isL3Pg (page_desc_t *page) { return page->type == PG_L3; }
static inline int isL4Pg (page_desc_t *page) { return page->type == PG_L4; }
static inline int isSVAPg (page_desc_t *page) { return page->type == PG_SVA; }
static inline int isCodePg (page_desc_t *page) { return page->type == PG_CODE; }
static inline int isGhostPTP (page_desc_t *page) { return page->ghostPTP; }

static inline int isGhostPG (page_desc_t *page) { 
    return page->type == PG_GHOST; 
}

static inline int isKernelStackPG(page_desc_t *page) { 
    return !page->user && page->stack; 
}

static inline int isPTP (page_desc_t *pg) { 
    return  pg->type == PG_L4    ||  
            pg->type == PG_L3    ||  
            pg->type == PG_L2    ||  
            pg->type == PG_L1
            ;
}

static inline int isUserMapping (page_entry_t mapping) { return (mapping & PG_U);}
static inline int isUserPTP (page_desc_t *page) { return isPTP(page) && page->user;}
static inline int isUserPG (page_desc_t *page){ return page->user; }
static inline int isCodePG (page_desc_t *page){ return page->code; }

/*
 * Function: readOnlyPage
 *
 * Description: 
 *  This function determines whether or not the given page descriptor
 *  references a page that should be marked as read only. We set this for pages
 *  of type: l4,l3,l2,l1, code, and TODO: is this all of them?
 *
 * Inputs:
 *  pg  - page descriptor to check
 *
 * Return:
 *  - 0 denotes not a read only page
 *  - 1 denotes a read only page
 */
static inline int
readOnlyPageType(page_desc_t *pg) {
  return  (pg->type == PG_L4)
           || (pg->type == PG_L3)
           || (pg->type == PG_L2)
#if 0
           || (pg->type == PG_L1)
#endif
           || (pg->type == PG_CODE)
           || (pg->type == PG_SVA)
           ;
}

/*
 * Function: mapPageReadOnly
 *
 * Description:
 *  This function determines if the particular page-translation-page entry in
 *  combination with the new mapping necessitates setting the new mapping as
 *  read only. The first thing to check is whether or not the new page needs to
 *  be marked as read only. The second issue is to distinguish between the case
 *  when the new read only page is being inserted as a page-translation-page
 *  reference or as the lookup value for a given VA by the MMU. The latter case
 *  is the only we mark as read only, which will protect the page from writes
 *  if the WP bit in CR0 is set. 
 *
 * Inputs:
 *  ptePG    - The page descriptor of the page that we are inserting into the
 *             page table.  We will use this to determine if we are adding
 *             a page table page.
 *
 *  mapping - The mapping that will be used to insert the page.  This is used
 *            for cases in which what would ordinarily be a page table page is
 *            a large data page.
 *
 * Return value:
 *  0 - The mapping can safely be made writeable.
 *  1 - The mapping should be read-only.
 */
static inline unsigned char 
mapPageReadOnly(page_desc_t * ptePG, page_entry_t mapping) {
  if (readOnlyPageType(getPageDescPtr(mapping))){
    /*
     * L1 pages should always be mapped read-only.
     */
    if (isL1Pg(ptePG))
      return 1;

    /* 
     * L2 and L3 pages should be mapped read-only unless they are data pages.
     */
    if ((isL2Pg(ptePG) || isL3Pg(ptePG) ) && (!(mapping & PG_PS)))
      return 1;
  }

  return 0;
}

/*
 * Function: protect_paging()
 *
 * Description:
 *  Actually enforce read only protection. 
 *
 *  Protects the page table entry. This disables the flag in CR0 which bypasses
 *  the RW flag in pagetables. After this call, it is safe to re-enable
 *  interrupts.
 */
static inline void
protect_paging(void) {
  /* The flag value for enabling page protection */
  const uintptr_t flag = 0x00010000;
  uintptr_t value = 0;
  __asm__ __volatile ("movq %%cr0,%0\n": "=r" (value));
  value |= flag;
  __asm__ __volatile ("movq %0,%%cr0\n": :"r" (value));
  return;
}

/*
 * Function: unprotect_paging
 *
 * Description:
 *  This function disables page protection on x86_64 systems.  It is used by
 *  the SVA VM to allow itself to disable protection to update the in-memory
 *  page tables.
 */
static inline void
unprotect_paging(void) {
  /* The flag value for enabling page protection */
  const uintptr_t flag = 0xfffffffffffeffff;
  uintptr_t value;
  __asm__ __volatile("movq %%cr0,%0\n": "=r"(value));
  value &= flag;
  __asm__ __volatile("movq %0,%%cr0\n": : "r"(value));
}


#endif

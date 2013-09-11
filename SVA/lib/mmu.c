/*===- mmu.h - SVA Execution Engine  =-------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * Note: We try to use the term "frame" to refer to a page of physical memory
 *       and a "page" to refer to the virtual addresses mapped to the page of
 *       physical memory.
 *
 *===----------------------------------------------------------------------===
 */

#include <string.h>

#include <sys/types.h>

#include "sva/callbacks.h"
#include "sva/mmu.h"
#include "sva/mmu_intrinsics.h"
#include "sva/x86.h"
#include "sva/state.h"
#include "sva/util.h"

/* 
 * Defines for #if #endif blocks for commenting out lines of code
 */
/* Used to denote unimplemented code */
#define NOT_YET_IMPLEMENTED 0   

/* Code that is under test and may cause issues */
#define UNDER_TEST          1   

/* Used to temporarily disable code for any reason */
#define TMP_DISABLED        0   

/* Used to denote obsolete code that hasn't been deleted yet */
#define OBSOLETE            0   

/* Denotes code that is in for some type of testing but is only temporary */
#define TMP_TEST_CODE       1

/* Denotes whether or not we are activating read only protection */
#define ACTIVATE_PROT       0

/* Define whether to enable DEBUG blocks #if statements */
#define DEBUG               0

/* Define whether or not the mmu_init code assumes virtual addresses */
#define USE_VIRT            0

/*
 *****************************************************************************
 * Function prototype declarations.
 *****************************************************************************
 */

/* 
 * Function prototypes for finding the virtual address of page table components
 */
static inline page_entry_t * get_pgeVaddr (uintptr_t vaddr);
static inline pml4e_t * get_pml4eVaddr (unsigned char * cr3, uintptr_t vaddr);
static inline pdpte_t * get_pdpteVaddr (pml4e_t * pml4e, uintptr_t vaddr);
static inline pde_t * get_pdeVaddr (pdpte_t * pdpte, uintptr_t vaddr);
static inline pte_t * get_pteVaddr (pde_t * pde, uintptr_t vaddr);

/*
 * Function prototypes for returning the physical address of page table pages.
 */
static inline uintptr_t get_pml4ePaddr (unsigned char * cr3, uintptr_t vaddr);
static inline uintptr_t get_pdptePaddr (pml4e_t * pml4e, uintptr_t vaddr);
static inline uintptr_t get_pdePaddr (pdpte_t * pdpte, uintptr_t vaddr);
static inline uintptr_t get_ptePaddr (pde_t * pde, uintptr_t vaddr);

/*
 * Mapping update function prototypes.
 */
static inline void __update_mapping (pte_t * pageEntryPtr, page_entry_t val);
static inline void __clean_and_restore_ptp (pte_t * pageEntryPtr);

/*
 *****************************************************************************
 * Define paging structures and related constants local to this source file
 *****************************************************************************
 */

/*
 * Struct: PTInfo
 *
 * Description:
 *  This structure contains information on pages fetched from the OS that are
 *  used for page table pages that the SVA VM creates for its own purposes
 *  (e.g., secure memory).
 */
struct PTInfo {
  /* Virtual address of page provided by the OS */
  unsigned char * vosaddr;

  /* Physical address to which the virtual address is mapped. */
  uintptr_t paddr;

  /* Number of uses in this page table page */
  unsigned short uses;

  /* Flags whether this entry is used */
  unsigned char valid;
};


/*
 * Structure: PTPages
 *
 * Description:
 *  This table records information on pages fetched from the operating system
 *  that the SVA VM will use for its own purposes.
 */
struct PTInfo PTPages[1024];

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
page_desc_t * getPageDescPtr(unsigned long mapping) {
  unsigned long frameIndex = (mapping & PG_FRAME) / pageSize;
  if (frameIndex >= numPageDescEntries)
    panic ("SVA: getPageDescPtr: %lx %lx\n", frameIndex, numPageDescEntries);
  return page_desc + frameIndex;
}

/*
 * Function: init_mmu
 *
 * Description:
 *  Initialize MMU data structures.
 */
void 
init_mmu () {
  /* Initialize the page descriptor array */
  memset (page_desc, 0, sizeof (struct page_desc_t) * numPageDescEntries);
  return;
}

/*
 *****************************************************************************
 * Define helper functions for MMU operations
 *****************************************************************************
 */

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

/*
 * Function: canBeDeclared()
 *
 * Description:
 *  Determine if the page described by the specified page descriptor can be
 *  declared as a page table page.
 */
static inline unsigned char
canBeDeclared (page_desc_t * pgDesc) {
  unsigned char canDeclare = 1;
  switch (pgDesc->type) {
    case PG_L1:
    case PG_L2:
    case PG_L3:
    case PG_L4:
    case PG_LEAF:
    case PG_TKDATA:
    case PG_TUDATA:
    case PG_CODE:
    case PG_SVA:
    case PG_GHOST:
      canDeclare = 0;
      break;
    default:
      break;
  }

  return canDeclare;
}

/* Functions for aiding in declare and updating of page tables */

/*
 * Function: page_entry_store
 *
 * Description:
 *  This function takes a pointer to a page table entry and updates its value
 *  to the new value provided.
 *
 * Assumptions: 
 *  - This function assumes that write protection is enabled in CR0 (WP bit set
 *    to 1). 
 *
 * Inputs:
 *  *page_entry -: A pointer to the page entry to store the new value to, a
 *                 valid VA for accessing the page_entry.
 *  newVal      -: The new value to store, including the address of the
 *                 referenced page.
 *
 * Side Effect:
 *  - This function enables system wide write protection in CR0. 
 *    
 *
 */
static inline void
page_entry_store (unsigned long *page_entry, page_entry_t newVal) {
    
#if ACTIVATE_PROT
  /* Disable page protection so we can write to the referencing table entry */
  unprotect_paging();
#endif
    
#if DEBUG >= 5
  printf("##### SVA<page_entry_store>: pre-write ");
  printf("Addr:0x%p, Val:0x%lx: \n", page_entry, *page_entry);
#endif
    
    /* Write the new value to the page_entry */
    *page_entry = newVal;

#if DEBUG >= 5
  printf("##### SVA<page_entry_store>: post-write ");
  printf("Addr:0x%p, Val:0x%lx \n", page_entry, *page_entry);
#endif

#if ACTIVATE_PROT
  /* Reenable page protection */
  protect_paging();
#endif
}

/*
 *****************************************************************************
 * Page table page index and entry lookups 
 *****************************************************************************
 */

/*
 * Function: is_correct_pe_for_va 
 *
 * Description: This function verifies that the mapping being inserted is
 *      correct by checking that the va address being mapped into this
 *      particular page table entry should be in that address location.
 *
 *      To prove that we have a valid ordering we can just verify that the
 *      update is being applied to the correct page table (at any level) and
 *      that the particuler page table entry (at any level) is at the index
 *      defined by the virtual address.
 *
 * Inputs:
 *  
 */
static inline int 
is_correct_pe_for_va (uintptr_t testPgEPAddr, page_desc_t *newPG, uintptr_t vaddr)
{
    /* Variables to hold temporary address values */
    pml4e_t *pml4e;
    pdpte_t *pdpte;
    pde_t *pde;
    pte_t *pte;

    /* Set the page type variable for later use */
    enum page_type_t pglevel = newPG->type;

    /*
     * Get the currently active page table.
     */
    unsigned char * cr3 = get_pagetable();

    /* 
     * We need to get the physical address matching the page table page level
     * and virtual address.
     */
    uintptr_t truePgEPAddr;

    if (pglevel == PG_L4) {

        truePgEPAddr = get_pml4ePaddr(cr3, vaddr);

    } else if (pglevel == PG_L3) {

        pml4e = get_pml4eVaddr (cr3, vaddr);
        truePgEPAddr = get_pdptePaddr (pml4e, vaddr);

    } else if (pglevel == PG_L2) {

        pml4e = get_pml4eVaddr (cr3, vaddr);
        pdpte = get_pdpteVaddr (pml4e, vaddr);
        truePgEPAddr = get_pdePaddr (pdpte, vaddr);

    } else if (pglevel == PG_L1) {

        pml4e = get_pml4eVaddr (cr3, vaddr);
        pdpte = get_pdpteVaddr (pml4e, vaddr);
        pde = get_pdeVaddr (pdpte, vaddr);
        truePgEPAddr = get_ptePaddr (pde, vaddr);

    } 

    /* 
     * To make sure we have the correct page entry we compare the physical
     * address of the entry under test with the physical address of the new
     * entry from the VA.
     */
    return testPgEPAddr == truePgEPAddr;
}

/*
 * Function: pt_update_is_valid()
 *
 * Description:
 *  This function assesses a potential page table update for a valid mapping.
 *
 *  NOTE: This function assumes that the page being mapped in has already been
 *  declared and has its intial page metadata captured as defined in the
 *  initial mapping of the page.
 *
 * Inputs:
 *  *page_entry  - VA pointer to the page entry being modified
 *  newVal       - Representes the new value to write including the reference
 *                 to the underlying mapping.
 *
 * Return:
 *  0  - The update is not valid and should not be performed.
 *  ~0 - The update is valid and can be performed.
 */
static inline unsigned long
pt_update_is_valid (page_entry_t *page_entry, page_entry_t newVal) {
    /* Collect associated information for the existing mapping */
    unsigned long origPA = *page_entry & PG_FRAME;
    unsigned long origFrame = origPA >> PAGESHIFT;
    uintptr_t origVA = (uintptr_t) getVirtual(origPA);
    page_desc_t *origPG = &page_desc[origFrame];

    /* Get associated information for the new page being mapped */
    unsigned long newPA = newVal & PG_FRAME;
    unsigned long newFrame = newPA >> PAGESHIFT;
    uintptr_t newVA = (uintptr_t) getVirtual(newPA);
    page_desc_t *newPG = &page_desc[newFrame];

    /* Get the page table page descriptor. The page_entry is the viratu */
    uintptr_t ptePAddr = getPhysicalAddr (page_entry);
    page_desc_t *ptePG = getPageDescPtr(ptePAddr);

    /* 
     * If we aren't mapping a new page then we can skip several checks, and in
     * some cases we must, otherwise, the checks will fail. For example if this
     * is a mapping in a page table page then we allow a zero mapping. 
     */
    if(newVal & PG_V){

        /* If the new mapping references a secure memory page fail */
        SVA_ASSERT (!isGhostPG(newPG), "MMU: Kernel attempted to map a secure page");


        /* If the mapping is to an SVA page then fail */
        SVA_ASSERT (!isSVAPg(newPG), "Kernel attempted to map an SVA page");

#if OBSOLETE
        /*
         * If new mapping is to a physical page that is used in a kernel stack, flag
         * an error.
         */
        SVA_NOOP_ASSERT (!isKernelStackPG(newPG), "Kernel attempted to double map a stack page");
#endif
    
        /* 
         * If the new page is a page table page then we verify some page table
         * page specific checks. 
         *
         * TODO: for better code design this can be refactored into a single
         * function.
         */
        if (isPTP(newPG)) {

            /* 
             * If we have a page table page being mapped in and it currently
             * has a mapping to it, then we verify that the new VA from the new
             * mapping matches the existing currently mapped VA. 
             *
             * This guarantees that we have at most one VA mapping to each page
             * table page.
             */
            if (pgRefCount(newPG) > 0) {
#if 0
                SVA_NOOP_ASSERT(pgVA(newPG) == newVA, 
                        "MMU: attempted to insert mappping to a second VA for PTP");
#endif
            }
        }
    }
        
    /* 
     * If the virtual address of the page_entry is in secure memory then fail,
     * as the kernel will never be allowed to map any VA mapping that region. 
     */
    SVA_ASSERT (!isGhostVA((uintptr_t) page_entry), 
            "MMU: Kernel attempted to map into a secure page table page");

    /* If the pt entry resides in a ghost page table page then fail */
    SVA_ASSERT (!isGhostPTP(ptePG), 
            "MMU: Kernel attempted to map into an SVA page table page");

    /*
     * If the new mapping is set for user access, but the VA being used is to
     * kernel space, fail. Also capture in this check is if the new mapping is
     * set for super user access, but the VA being used is to user space, fail.
     *
     * 3 things to assess for matches: 
     *  - U/S Flag of new mapping
     *  - Type of the new mapping frame
     *  - Type of the PTE frame
     * 
     * Ensures the new mapping U/S flag matches the PT page frame type and the
     * mapped in frame's page type, as well as no mapping kernel code pages
     * into userspace.
     */
    
    /* 
     * TODO: this functionality depends on the pages in question being marked
     * as kernel or user page privilege. Once that functionality is added then
     * this check can be enabled. The function doing this is 
     * check_and_init_first_mapping.
     */

    SVA_NOOP_ASSERT ( 
            (isUserMapping(newVal) && isUserPTP(ptePG) && isUserPG(newPG)) ||
            (!isUserMapping(newVal) && !isUserPTP(ptePG) && !isUserPG(newPG)) , 
            "MMU: all three -- mapping, new page frame, and PTP -- do not match privilege");

    /* 
     * If the original PA is not equivalent to the new PA then we are creating
     * an entirely new mapping, thus make sure that this is a valid new page
     * reference. Also verify that the reference counts to the old page are
     * sane, i.e., there is at least a current count of 1 to it. 
     */
    if (origPA != newPA) {
#if OBSOLETE
        /* 
         * TODO: I need to think about this more to make sure I understand why
         * this check is necessary. 
         */
         /* If the old mapping was to a stack fail */
        SVA_NOOP_ASSERT (!isStackPG(origPG));
#endif
            
        /* 
         * If the old mapping was to a code page then we know we shouldn't be
         * pointing this entry to another code page, thus fail.
         */
        SVA_NOOP_ASSERT (!isCodePG(origPG), 
                "Kernel attempting to modify code page mapping");
    
        /* 
         * When removing a mapping to a page table page by setting the new
         * reference to zero, verify that the reference count to the old page
         * table page will not be reduced to less than zero. 
         */
        /* 
         * FIXME: the code to increment reference counts is broken. It happens
         * in __do_mmu_update. The code is there but currently commented out.
         * We can't turn this assertion on until that is setup because it will
         * alwasy be zero presently.
         */
        SVA_NOOP_ASSERT(pgRefCount(origPG) >= minRefCountToRemoveMapping, 
                "MMU: Attempted to remove a mapping to a page with count of 0");
        
        /* 
         * Since we are adding a mapping to a new page, then we update the
         * count for the new page mapping. First check that we aren't
         * overflowing the counter.
         */
        SVA_NOOP_ASSERT (pgRefCount(newPG) < ((1<<12-1)), 
                "MMU: overflow for the mapping count");
    }

    /* TODO: do we need this check */

    /* 
     * Verify that the page we are mapping into is a page frame
     */
    SVA_NOOP_ASSERT (isPTP(ptePG), 
            "MMU: attempted mapping into a non-ptp page frame");

    /*
     * Verify that that the mapping matches the correct type of page
     * allowed to be mapped into this page table. Verify that the new
     * PTP is of the correct type given the page level of the page
     * entry. 
     */
    switch(ptePG->type) {
        case PG_L1:
            SVA_NOOP_ASSERT (isFramePg(newPG), 
                    "MMU: attempted to map non-frame page into L1.");
            break;
        case PG_L2:
            SVA_NOOP_ASSERT (isL1Pg(newPG), 
                    "MMU: attempted to map non-L1 page into L2.");
            break;
        case PG_L3:
            SVA_NOOP_ASSERT (isL2Pg(newPG), 
                    "MMU: attempted to map non-L2 page into L3.");
            break;
        case PG_L4:
            /* 
             * FreeBSD inserts a self mapping into the pml4, therefore it is
             * valid to map in an L4 page into the L4. TODO: consider the
             * security implications of this...
             */
            SVA_NOOP_ASSERT (isL3Pg(newPG) || isL4Pg(newPG), 
                    "MMU: attempted to map non-L3/L4 page into L4.");
            break;
        default:
            /* 
             * TODO when enabling this we will have had to finish the init and
             * remove code 
             */
            SVA_NOOP_ASSERT (0,
                    "MMU attempted to make update to non page table page.");
    }
    
    /* 
     * TODO There might be a bug in this lookup, as it doesn't account for PS=1
     * pages e.g., 2MB or 1GB pages. 
     */
    /* 
     * Verify that we have the correct PTE for the given VA.
     */
    SVA_NOOP_ASSERT (is_correct_pe_for_va(ptePAddr, ptePG, newVA) , 
            "MMU: attempted mapping of VA into either wrong page table page or wrong index into the page");

    return 1;

#if OBSOLETE
    void* pagetable = get_pagetable();
    unsigned long new_index = pte_val(val) >> PAGE_SHIFT;

    /*
     * If the new entry is a level1, level2 or code page, disable the RW flag
     */
    if (new_index && likely(pte_val(val) & _PAGE_RW)) {
        if (unlikely(page_desc[new_index].l1 ||
                    page_desc[new_index].l2 ||
                    page_desc[new_index].code)) {
            val = __pte(pte_val(val) & ~_PAGE_RW);
        }
    }

    /*
     * Ensure that this mapping does not create a mapping into a page used by the
     * SVA virtual machine.
     */
    if (unlikely(page_desc[new_index].sva))
        poolcheckfail("MMU: try to map a sva pag: %x", __builtin_return_address(0));

    /*
     * Get the virtual to physical page mapping that is already within the
     * page table.
     */
    pte_t old_mapping = *pteptr;
    unsigned long old_index = pte_val(old_mapping) >> PAGE_SHIFT;

    if (new_index) {
        /*
         * If the new entry is maps to a physical page that belongs to a Type-Known
         * MetaPool, flag an error.
         */
        if (page_desc[new_index].typed) {
            poolcheckfail("MMU: try to double map a type known page: ", new_index, __builtin_return_address(0));
        }

        /*
         * If we're creating a new mapping to a physical page that is used in a
         * kernel stack, flag an error.
         */
        if (page_desc[new_index].stack) {
            poolcheckfail("MMU: try to double map a stack page: %x", __builtin_return_address(0));
        }

        /*
         * If we're creating a virtual mapping that is accessible only in
         * kernel-space, but the page is accessible via some user-space mapping,
         * flag an error.
         */
#if 0
        if (((pte_val(val)) & PTE_CANUSER) == 0) {
            if (page_desc[new_index].user) {
                poolcheckfail("Mapping user-accessible page into the kernel",
                        new_index, __builtin_return_address(0));
            }
        } else {
            if (page_desc[new_index].kernel) {
                poolcheckfail("Mapping kernel-accessible page into user-space",
                        new_index, __builtin_return_address(0));
            }
        }
#endif

#if 0
        /*
         * If the new mapping wants to make the page accessible to user-space but
         * the page currently contains typed or untyped kernel objects, then the
         * caller is trying to make kernel memory objects accessible to user-space
         * programs.  Do not permit such treachery!
         */
        if ((((pte_val(val)) & PTE_CANUSER) == 1) &&
                (page_desc[new_index].typed || page_desc[new_index].untyped)) {
            poolcheckfail("MMU: Mapping kernel page into user-space: ",
                    new_index, __builtin_return_address(0));
        }
#endif

        /*
         * If the frame is currently accessible by user-space code and the new
         * translation will map the page into the kernel's address space, report an
         * error.  Oh, and do not permit such treachery!.
         */
        if (page_desc[new_index].user && is_l1_kernel_page(pteptr)) {
            pte_t* kpte = get_pte((unsigned long)pteptr, get_pagetable());
            unsigned long kpa;
            kpa = pte_val(*kpte) >> PAGE_SHIFT;
            poolcheckfail("MMU: Mapping user-accessible page into kernel-space: ",
                    new_index, kpa);
        }
    }

    if (old_index) {
        if (unlikely(page_desc[old_index].stack)) {
            poolcheckfail("MMU: try to modify the mapping of a stack: %x", __builtin_return_address(0));
        }
        /** NDD NOTES:
         * If the old was an sva page, then the pte entry will be an entry in
         * an sva page table, and thus be captured when we check to see if we
         * are mapping into an sva page table page. Thus, this check is
         * superceeded by the check to see if we are mapping into an SVA page. 
         */
        if (unlikely(page_desc[old_index].sva))
            poolcheckfail("MMU: try to modify the mapping of a sva page: %x", __builtin_return_address(0));
        /** NDD NOTES:
         * This check is saying that a code mapping should never change... 
         */
        if (unlikely(page_desc[old_index].code))
            poolcheckfail("MMU: try to modify the mapping of kernel code: %x", __builtin_return_address(0));
    }

    /* Update the mapping count of the old and new mapped physical pages */
    if (old_index) {  
        page_desc[old_index].count--;
        /* If there is no mapping of the page, we can remove the untyped flag,
           so that the page can be used by users. */
        if (page_desc[old_index].count == 0) {
            page_desc[old_index].untyped = 0;
            page_desc[old_index].user = 0;
        }
    }
    
    if (new_index) {
        if (page_desc[new_index].count < ((1 << 12) - 1)) {
            page_desc[new_index].count++;
        } else {
            poolcheckfail("MMU: overflow for mapping count %x", __builtin_return_address(0));
        }

        /*
         * If the new translation makes the page accessible to user-space programs,
         * mark the physical page frame as accessible from user-space.
         */
        if (((pte_val(val)) & PTE_CANUSER) == 1) {
            page_desc[new_index].user = 1;
        }
    }

    /* OBSOLETE NOTE: This is obsolete because this function assumes all pages
     * have already been declared and intialized based upon that inital
     * declare. This means that we should not hit an instance where an update
     * is going to change the user/super flag.
     */
    /*
     * If the new mapping makes the page available to user-space, record that.
     */
    if (((pte_val(val)) & PTE_CANUSER)) {
        page_desc[new_index].user = 1;
    } else {
        page_desc[new_index].kernel = 1;
    }
#endif

}

/*
 * Function: 
 *
 * Description:
 *
 * Inputs:
 */
static inline void 
setPgPrivMode (page_desc_t *pg, uintptr_t va) {
    page_entry_t *pe;
    switch(pg->type){
        case PG_L4:
            //pe = va_to_pml4VA(va);
        case PG_L3:
        case PG_L2:
        case PG_L1:
        default:
            break;
    }
}

/*
 * Function: updateNewPageData
 *
 * Description: 
 *  This function is called whenever we are inserting a new mapping into a page
 *  entry. The goal is to manage any SVA page data that needs to be set for
 *  tracking the new mapping with the existing page data. This is essential to
 *  enable the mmu verification checks.
 *
 * Inputs:
 *  - mapping : the new mapping to be inserted
 */
static inline void
updateNewPageData(page_entry_t mapping) {
    uintptr_t newPA = mapping & PG_FRAME;
    unsigned long newFrame = newPA >> PAGESHIFT;
    uintptr_t newVA = (uintptr_t) getVirtual(newPA);
    page_desc_t *newPG = getPageDescPtr(mapping);

    /*
     * If the new mapping is valid then update the counts for it.
     */
#if NOT_YET_IMPLEMENTED
    if (mapping & PG_V) {

        /* There is a bug when we modify counts on page_desc[0] so skip */
        if(newFrame != 0) {

            //printf("SVA: new page update [pdesc:%p][*pte:%p][PA:%p][VA:%p][pre-count:%lu]\n",
            //newPG, val, newPA, newVA, newPG->count);
            /*
             * If the new page is to a PTP and this is the first reference to
             * the page, we need to set the VA mapping this page so that the
             * verification routine can enforce that this page is only mapped
             * to a single VA. Note that if we have gotten here, we know that
             * we currently do not have a mapping to this page already, which
             * means this is the first mapping to the page. 
             */
#if 0
            if (isPTP(newPG)){
                setPTPVA(newPG, newVA);
            }
#endif

            /* There is some type of bug with this update. */
            newPG->count++;
        } else {
            /* 
             * FIXME:XXX this case has a bug when updating the metadata.
             * Figure it out 
             */
        }

        /* 
         * Set the privilege mode of this entry given the VA 
         */
        //setPrivMode(newPG, newVA);

        /* 
         * Set the VA of this entry if it is the first mapping to a page
         * table page.
         */
    }
#endif
}

/*
 * Function: updateOrigPageData
 *
 * Description:
 *  This function updates the metadata for a page that is being removed from
 *  the mapping. 
 * 
 * Inputs:
 *  - mapping : the mapping for the old page
 */
static inline void
updateOrigPageData(page_entry_t mapping){
    uintptr_t origPA = mapping & PG_FRAME; 
    unsigned long origFrame = origPA >> PAGESHIFT;
    uintptr_t origVA = (uintptr_t) getVirtual(origPA);
    page_desc_t *origPG = &page_desc[origFrame];

    /* FIXME:TODO there is a special case where the original page could be
     * invalid or non-existent. I can think of two cases actually: 
     *  - a zero mapping meaning it is non-existent
     *  - a non-zero real address mapping but with the valid bit set to 0
     *  - a non-zero valid mapping 
     *
     *  The real issue is figuring out whether or not an invalidate mapping
     *  removes the mapping and clears it. The one case is true though in
     *  that we don't decrement unless we have a value in the old mapping.
     */
    /* 
     * Only decrement the mapping count if the page has an existing
     * valid mapping.
     */
    //if((*pteptr & PG_V) && origPA != 0) 
    if((mapping & PG_V)) {

#if NOT_YET_IMPLEMENTED
        /* There is a bug when we modify counts on page_desc[0] so skip */
        if(origFrame != 0) {

            /* Update the mapping count of the old and new mapped physical pages */
            origPG->count--;

        } else {
            /* 
             * FIXME:XXX this case has a bug when updating the metadata.
             * Figure it out 
             */
            printf("Decremented ref count [pdesc:%p][*pte:%p][PA:%p][VA:%p][pre-count:%lu]\n",
                    origPG, mapping, origPA, origVA, origPG->count);
        }
#endif

#if NOT_YET_IMPLEMENTED
        /* 
         * TODO: what happens if the count is already zero here? For example
         * when we remove a page, do we zero out the references to it from the
         * PTs or do we just do an invalidate update?
         */
        if (pgRefCount(origPG) == 0) {
            removePage(origPG);
        }
#endif
    }
}

/*
 * Function: __do_mmu_update
 *
 * Description:
 *  If the update has been validated this function manages metadata by updating
 *  the internal SVA reference counts for pages, sets the read only flag if
 *  necessary, and then performs the actual update. 
 *
 * Inputs: 
 *  *page_entry  - VA pointer to the page entry being modified 
 *  newVal       - Representes the mapping to insert into the page_entry
 */
static inline void
__do_mmu_update (pte_t * pteptr, page_entry_t mapping) {
    uintptr_t origPA = *pteptr & PG_FRAME;
    uintptr_t newPA = mapping & PG_FRAME;

    /*
     * If we have a new mapping as opposed to just changing the flags of an
     * existing mapping, then update the sva meta data for the pages. We know
     * that we have passed the validation checks so these updates have been
     * vetted.
     */
    if (newPA != origPA) {
        updateOrigPageData(*pteptr);
        updateNewPageData(mapping);
    }

#if ACTIVATE_PROT
    /* If the new page should be read only, mark the entry value as such */
    if (mapPageReadOnly(getPageDescPtr(*pteptr), mapping)) {
        mapping = setMappingReadOnly(mapping);
    }
#endif

    /* perform the actual write to the pte entry */
    page_entry_store ((page_entry_t *) pteptr, mapping);
}

/*
 * Function: init_page_entry
 *
 * Description:
 *  This function zeros out the physical page pointed to by frameAddr and sets
 *  as read only the page_entry. The page_entry is agnostic as to which level
 *  page table entry we are modifying, because the format of the entry is the
 *  same in all cases. 
 *
 * Assumption: This function should only be called by a declare intrinsic.
 *      Otherwise it has side effects that may break the system.
 *
 * Inputs:
 *  frameAddr: represents the physical address of this frame
 *
 *  *page_entry: A pointer to a page table entry that will be used to
 *      initialize the mapping to this newly created page as read only. Note
 *      that the address of the page_entry must be a virtually accessible
 *      address.
 */
static inline void 
init_page_entry (unsigned long frameAddr) {
  /*
   * Get the direct map virtual address of the physical address.
   */
  unsigned char * vaddr = getVirtual (frameAddr);

  /*
   * Initialize the contents of the page to zero.  This will ensure that no
   * existing page translations which have not been vetted exist within the
   * page.
   */
  memset (vaddr, 0, X86_PAGE_SIZE);

  /*
   * Get a pointer to the page table entry that maps the physical page into the
   * direct map.
   */
  page_entry_t * page_entry = get_pgeVaddr (vaddr);
#if UNDER_TEST
#if ACTIVATE_PROT
  /*
   * If this should be marked as a read only page, set the RO flag of the pde
   * referencing this new page. This is an update type operation. A value of
   * 0 in bit position 2 configures for no writes.
   */
  if (readOnlyPageType(getPageDescPtr(frameAddr))) {
    page_entry_t newMapping = *page_entry;
    newMapping = setMappingReadOnly(newMapping);

    /* Perform the actual store of the value to the page_entry */
    page_entry_store(page_entry, newMapping);
  }
#endif

#else
  /* TODO:
   * In the end we want to use this to insert the new declared PTPs so they
   * pass validation as they are real PTP updates. 
   */
  __update_mapping(page_entry, *page_entry);
#endif
}

/*
 * Function: 
 */
static inline void
setFramePrivType (unsigned long frame, unsigned long newMapping){
#if NOT_YET_IMPLEMENTED
    page_desc_t pgDesc = page_desc[frame];
    /* 
     * TODO: Figure out how to detect the user/kernel association of new page
     * table pages.
     */

    /*
     * TODO: figure out whether or not this is a leaf frame or a page table
     * page frame. If it is a frame then the type is given by the newMapping
     * value. If it is a page table frame then I need to figure out how to
     * figure out the mapping.
     */
    if (){
    }
    /* If the new mapping points to user level */
    if (isUserVA(newVA)){
    } else {
    }
#endif
}

/*
 * Function: isFirstMappingToFrame
 *
 * Description:
 *  This function determines whether or not this frame has any existing
 *  references.
 *
 * Input:
 *  - frame : the physical frame number to check
 *
 * Return:
 *  - 1: true, the first mapping
 *  - 0: false, this frame has an existing mapping
 */
static inline int
isFirstMappingToFrame (unsigned long frame) {
    /* SVA_ASSERT here just in case we have some odd error situation */
#if NOT_YET_IMPLEMENTED
    printf("The page frame count %d\n",page_desc[frame].count);
    SVA_ASSERT (page_desc[frame].count >= 0, "MMU: page count is negative");
#endif

    /* 
     * If the count is set to 0 then there are no existing references to this
     * frame.
     */
    return page_desc[frame].count == 0;
}

/*
 * Function: check_and_init_first_mapping
 *
 * Description:
 *  There are certain labels that must be applied to a particular frame that
 *  can only be applied when using it's first mapping. Currently, the only
 *  thing that is needed upon first mapping is to label the page desc of the
 *  frame as either user or kernel depending on the new mapping.
 *
 * Input: 
 *  - newMapping    : Represents the new mapping to insert
 */
static inline void
check_and_init_first_mapping(unsigned long newMapping){

    /* Get the frame number in the new mapping */
    unsigned long frame = (newMapping & PG_FRAME) >> PAGESHIFT;

    /* 
     * If this is the first mapping to the frame then set the privilege on the
     * frame. 
     */
    if (isFirstMappingToFrame(frame))
        setFramePrivType(frame, newMapping);
}

/*
 * Function: __update_mapping
 *
 * Description:
 *  Mapping update function that is agnostic to the level of page table. Most
 *  of the verification code is consistent regardless of which level page
 *  update we are doing. 
 *
 * Inputs:
 *  - pageEntryPtr : reference to the page table entry to insert the mapping
 *      into
 *  - val : new entry value
 */
static inline void
__update_mapping (pte_t * pageEntryPtr, page_entry_t val) {
  unsigned long rflags;

  /* Disable interrupts so that we appear to execute as a single instruction. */
  rflags = sva_enter_critical();

  /* 
   * If this is the first mapping to the page then establish initial values
   * for page types 
   */
#if NOT_YET_IMPLEMENTED
  check_and_init_first_mapping(val);
#endif

  /* 
   * If the given page update is valid then store the new value to the page
   * table entry, else raise an error.
   */
  if (pt_update_is_valid((page_entry_t *) pageEntryPtr, val)) {
      /* Perform the pagetable mapping update */
      __do_mmu_update ((page_entry_t *) pageEntryPtr, val);
  } else {
      panic("##### SVA invalid page update!!!\n");
  }

  /* Restore interrupts */
  sva_exit_critical (rflags);
}

/*
 * Function: __clean_and_restore_ptp
 *
 * Description:
 *  This function takes a pte pointer to a page that has been identified as a
 *  protected page (PTPs as well as code pages) and releases the VG resources
 *  associated with the page, as well as zero and make the page writeable
 *  again. 
 *
 *  It is important to note that the pte for a page-translation-page will be a
 *  pte in the DMAP region. This is due to the fact that access to the PTPs is
 *  managed via that region as only one VA is given to each PTP. 
 *
 * Inputs:
 *  - pageEntryPtr  : A pointer to a pte that points to the given read only
 *                    page. 
 */
static inline void 
__clean_and_restore_ptp (pte_t * pageEntryPtr) {
  /* Get the page_desc for the newly declared l4 page frame */
  page_desc_t *pgDesc = getPageDescPtr(getPhysicalAddr (pageEntryPtr));

  /*
   * Check that there are no references to this page (i.e., there is no page
   * table entry that refers to this physical page frame).  If there is a
   * mapping, then someone is still using it as a page table page).
   */
  if (pgDesc->count) {
    panic ("SVA: sva_remove_mapping: Still referenced: %lx\n", pageEntryPtr);
  }

  /*
   * Mark the page frame as an unused page.
   */
  pgDesc->type = PG_UNUSED;

  /*
   * Make the page writeable again.  Be sure to disable page protection since
   * page table pages are not writeable.
   */
  unprotect_paging();
  __update_mapping (pageEntryPtr, setMappingReadWrite (*pageEntryPtr));
  protect_paging();

  return;
}

/* Functions for finding the virtual address of page table components */

/* 
 * Function: get_pgeVaddr
 *
 * Description:
 *  This function does page walk to find the entry controlling access to the
 *  specified address. The function takes into consideration the potential use
 *  of larger page sizes.
 * 
 * Inputs:
 *  - vaddr     : Virtual Address to find entry for
 */
static inline page_entry_t * 
get_pgeVaddr (uintptr_t vaddr) {
    page_entry_t *pge;

    /* Get the base of the pml4 to traverse */
    uintptr_t cr3 = get_pagetable();

    /* Get the VA of the pml4e for this vaddr */
    pml4e_t *pml4e = get_pml4eVaddr (cr3, vaddr);

    /* Get the VA of the pdpte for this vaddr */
    pdpte_t *pdpte = get_pdpteVaddr (pml4e, vaddr);

    /* 
     * The PDPE can be configurd in large page mode. If it is then we have the
     * entry corresponding to the given vaddr If not then we go deeper in the
     * page walk.
     */
    if(*pdpte & PG_PS) {
        pge = pdpte;
#if DEBUG >=5
        printf("Found PS=1 in PDPE: dealing with 1GB page\n");
#endif
    } else {
        /* Get the pde associated with this vaddr */
        pde_t *pde = get_pdeVaddr (pdpte, vaddr);
        
        /* 
         * As is the case with the pdpte, if the pde is configured for large
         * page size then we have the corresponding entry. Otherwise we need to
         * traverse one more level, which is the last. 
         */
        if (*pde & PG_PS) {
            pge = pde;
#if DEBUG >=5
            printf("Found PS=1 in PDE: dealing with 2MB page\n");
#endif
        }
        else 
            pge = get_pteVaddr (pde, vaddr);
    }
    
    /* Return the entry corresponding to this vaddr */
    return pge;
}

static inline pml4e_t *
get_pml4eVaddr (unsigned char * cr3, uintptr_t vaddr) {
  /* Offset into the page table */
  uintptr_t offset = ((vaddr >> 39) << 3) & vmask;
  return (pml4e_t *) getVirtual (((uintptr_t)cr3) + offset);
}

static inline pdpte_t *
get_pdpteVaddr (pml4e_t * pml4e, uintptr_t vaddr) {
  uintptr_t offset = ((vaddr  >> 30) << 3) & vmask;
  return (pdpte_t *) getVirtual ((*pml4e & 0x000ffffffffff000u) + offset);
}

static inline pde_t *
get_pdeVaddr (pdpte_t * pdpte, uintptr_t vaddr) {
  uintptr_t offset = ((vaddr  >> 21) << 3) & vmask;
  return (pde_t *) getVirtual ((*pdpte & 0x000ffffffffff000u) + offset);
}

static inline pte_t *
get_pteVaddr (pde_t * pde, uintptr_t vaddr) {
  uintptr_t offset = ((vaddr >> 12) << 3) & vmask;
  return (pte_t *) getVirtual ((*pde & 0x000ffffffffff000u) + offset);
}

/*
 * Functions for returing the physical address of page table pages.
 */
static inline uintptr_t
get_pml4ePaddr (unsigned char * cr3, uintptr_t vaddr) {
  /* Offset into the page table */
  uintptr_t offset = ((vaddr >> 39) << 3) & vmask;
  return (((uintptr_t)cr3) + offset);
}

static inline uintptr_t
get_pdptePaddr (pml4e_t * pml4e, uintptr_t vaddr) {
  uintptr_t offset = ((vaddr  >> 30) << 3) & vmask;
  return ((*pml4e & 0x000ffffffffff000u) + offset);
}

static inline uintptr_t
get_pdePaddr (pdpte_t * pdpte, uintptr_t vaddr) {
  uintptr_t offset = ((vaddr  >> 21) << 3) & vmask;
  return ((*pdpte & 0x000ffffffffff000u) + offset);
}

static inline uintptr_t
get_ptePaddr (pde_t * pde, uintptr_t vaddr) {
  uintptr_t offset = ((vaddr >> 12) << 3) & vmask;
  return ((*pde & 0x000ffffffffff000u) + offset);
}

/* Functions for querying information about a page table entry */
static inline unsigned char
isPresent (uintptr_t * pte) {
  return (*pte & 0x1u) ? 1u : 0u;
}

/*
 * Function: getPhysicalAddr()
 *
 * Description:
 *  Find the physical page number of the specified virtual address.
 */
uintptr_t
getPhysicalAddr (void * v) {
  /* Mask to get the proper number of bits from the virtual address */
  static const uintptr_t vmask = 0x0000000000000fffu;

  /* Virtual address to convert */
  uintptr_t vaddr  = ((uintptr_t) v);

  /* Offset into the page table */
  uintptr_t offset = 0;

  /*
   * Get the currently active page table.
   */
  unsigned char * cr3 = get_pagetable();

  /*
   * Get the address of the PML4e.
   */
  pml4e_t * pml4e = get_pml4eVaddr (cr3, vaddr);

  /*
   * Use the PML4E to get the address of the PDPTE.
   */
  pdpte_t * pdpte = get_pdpteVaddr (pml4e, vaddr);

  /*
   * Determine if the PDPTE has the PS flag set.  If so, then it's pointing to
   * a 1 GB page; return the physical address of that page.
   */
  if ((*pdpte) & PTE_PS) {
    return (*pdpte & 0x000fffffffffffffu) >> 30;
  }

  /*
   * Find the page directory entry table from the PDPTE value.
   */
  pde_t * pde = get_pdeVaddr (pdpte, vaddr);

  /*
   * Determine if the PDE has the PS flag set.  If so, then it's pointing to a
   * 2 MB page; return the physical address of that page.
   */
  if ((*pde) & PTE_PS) {
    return (*pde & 0x000fffffffe00000u) + (vaddr & 0x1fffffu);
  }

  /*
   * Find the PTE pointed to by this PDE.
   */
  pte_t * pte = get_pteVaddr (pde, vaddr);

  /*
   * Compute the physical address.
   */
  offset = vaddr & vmask;
  uintptr_t paddr = (*pte & 0x000ffffffffff000u) + offset;
  return paddr;
}

/* Cache of page table pages */
extern unsigned char
SVAPTPages[1024][X86_PAGE_SIZE];

/*
 * Function: allocPTPage()
 *
 * Description:
 *  This function allocates a page table page, initializes it, and returns it
 *  to the caller.
 */
static unsigned int
allocPTPage (void) {
  /* Index into the page table information array */
  unsigned int ptindex;

  /* Pointer to newly allocated memory */
  unsigned char * p;

  /*
   * Find an empty page table array entry to record information about this page
   * table page.  Note that we're a multi-processor system, so use an atomic to
   * keep things valid.
   *
   * Note that we leave the first entry reserved.  This permits us to use a
   * zero index to denote an invalid index.
   */
  for (ptindex = 1; ptindex < 1024; ++ptindex) {
    if (__sync_bool_compare_and_swap (&(PTPages[ptindex].valid), 0, 1)) {
      break;
    }
  }
  if (ptindex == 1024)
    panic ("SVA: allocPTPage: No more table space!\n");

  /*
   * Ask the system software for a page of memory.
   */
  if ((p = SVAPTPages[ptindex]) != 0) {
    /*
     * Initialize the memory.
     */
    memset (p, 0, X86_PAGE_SIZE);

    /*
     * Record the information about the page in the page table page array.
     * We'll need the virtual address by which the system software knows the
     * page as well as the physical address so that the SVA VM can unmap it
     * later.
     */
    PTPages[ptindex].vosaddr = p;
    PTPages[ptindex].paddr   = getPhysicalAddr (p);

    /*
     * Return the index in the table.
     */
    return ptindex;
  }

  return 0;
}

/*
 * Function: freePTPage()
 *
 * Description:
 *  Return an SVA VM page table page back to the operating system for use.
 */
void
freePTPage (unsigned int ptindex) {
  /*
   * Mark the entry in the page table page array as available.
   */
  PTPages[ptindex].valid = 0;
  return;
}

/*
 * Function: updateUses()
 *
 * Description:
 *  This function will update the number of present entries within a page table
 *  page that was allocated by the SVA VM.
 *
 * Inputs:
 *  ptp - A pointer to the page table page.  This does not need to be a page
 *        table page owned by the SVA VM.
 */
static void
updateUses (uintptr_t * ptp) {
  /* Page table page array index */
  unsigned int ptindex;

  /*
   * Find the physical address to which this virtual address is mapped.  We'll
   * use it to determine if this is an SVA VM page.
   */
  uintptr_t paddr = getPhysicalAddr (ptp) & 0xfffffffffffff000u;

  /*
   * Look for the page table page with the specified physical address.  If we
   * find it, increment the number of uses.
   */
  for (ptindex = 0; ptindex < 1024; ++ptindex) {
    if (paddr == PTPages[ptindex].paddr) {
      ++PTPages[ptindex].uses;
    }
  }

  return;
}

/*
 * Function: releaseUse()
 *
 * Description:
 *  This function will decrement the number of present entries within a page
 *  table page allocated by the SVA VM.
 *
 * Inputs:
 *  pde - A pointer to the page table page.  This does not need to be an SVA VM
 *        page table page.
 *
 * Return value:
 *  0 - The page is not a SVA VM page table page, or the page still has live
 *      references in it.
 *  Otherwise, the index into the page table array will be returned.
 */
static unsigned int
releaseUse (uintptr_t * ptp) {
  /* Page table page array index */
  unsigned int ptindex;

  /*
   * Find the physical address to which this virtual address is mapped.  We'll
   * use it to determine if this is an SVA VM page.
   */
  uintptr_t paddr = getPhysicalAddr (ptp) & 0xfffffffffffff000u;

  /*
   * Look for the page table page with the specified physical address.  If we
   * find it, decrement the uses.
   */
  for (ptindex = 0; ptindex < 1024; ++ptindex) {
    if (paddr == PTPages[ptindex].paddr) {
      if ((--(PTPages[ptindex].uses)) == 0) {
        return ptindex;
      }
    }
  }

  return 0;
}

/*
 * Function: mapSecurePage()
 *
 * Description:
 *  Map a single frame of secure memory into the specified virtual address.
 *
 * Inputs:
 *  vaddr - The virtual address into which to map the physical page frame.
 *  paddr - The physical address of the page frame to map.
 *
 * Return value:
 *  The value of the PML4E entry mapping the secure memory region is returned.
 */
uintptr_t
mapSecurePage (unsigned char * v, uintptr_t paddr) {
  /* PML4e value for the secure memory region */
  pml4e_t pml4eVal;

  /*
   * Get the PML4E of the current page table.  If there isn't one in the
   * table, add one.
   */
  uintptr_t vaddr = (uintptr_t) v;
  pml4e_t * pml4e = get_pml4eVaddr (get_pagetable(), vaddr);

  if (!isPresent (pml4e)) {
    /* Page table page index */
    unsigned int ptindex;

    printf ("SVA: mapSecurePage: No PML4E: %lx\n", pml4e);

    /* Fetch a new page table page */
    ptindex = allocPTPage ();

    /*
     * Install a new PDPTE entry using the page.
     */
    uintptr_t paddr = PTPages[ptindex].paddr;
    *pml4e = (paddr & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;
  }

  /*
   * Enable writing to the virtual address space used for secure memory.
   */
  *pml4e |= PTE_CANUSER;

  /*
   * Record the value of the PML4E so that we can return it to the caller.
   */
  pml4eVal = *pml4e;

  /*
   * Get the PDPTE entry (or add it if it is not present).
   */
  pdpte_t * pdpte = get_pdpteVaddr (pml4e, vaddr);
  if (!isPresent (pdpte)) {
    /* Page table page index */
    unsigned int ptindex;

    printf ("SVA: mapSecurePage: No PDPTE!\n");

    /* Fetch a new page table page */
    ptindex = allocPTPage ();

    /*
     * Install a new PDPTE entry using the page.
     */
    uintptr_t pdpte_paddr = PTPages[ptindex].paddr;
    *pdpte = (pdpte_paddr & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;
  }
  *pdpte |= PTE_CANUSER;

  /*
   * Note that we've added another translation to the pml4e.
   */
  updateUses (pdpte);

  if ((*pdpte) & PTE_PS) {
    printf ("mapSecurePage: PDPTE has PS BIT\n");
  }

  /*
   * Get the PDE entry (or add it if it is not present).
   */
  pde_t * pde = get_pdeVaddr (pdpte, vaddr);
  if (!isPresent (pde)) {
    /* Page table page index */
    unsigned int ptindex;

    printf ("SVA: mapSecurePage: No PDE!\n");

    /* Fetch a new page table page */
    ptindex = allocPTPage ();

    /*
     * Install a new PDE entry.
     */
    uintptr_t pde_paddr = PTPages[ptindex].paddr;
    *pde = (pde_paddr & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;
  }
  *pde |= PTE_CANUSER;

  /*
   * Note that we've added another translation to the pdpte.
   */
  updateUses (pde);

  if ((*pde) & PTE_PS) {
    printf ("mapSecurePage: PDE has PS BIT\n");
  }

  /*
   * Get the PTE entry (or add it if it is not present).
   */
  pte_t * pte = get_pteVaddr (pde, vaddr);
#if 0
  if (isPresent (pte)) {
    panic ("SVA: mapSecurePage: PTE is present: %p!\n", pte);
  }
#endif

  /*
   * Modify the PTE to install the physical to virtual page mapping.
   */
  *pte = (paddr & addrmask) | PTE_CANWRITE | PTE_CANUSER | PTE_PRESENT;

  /*
   * Note that we've added another translation to the pde.
   */
  updateUses (pte);

  /*
   * Mark the physical page frame as a ghost memory page frame.
   */
  getPageDescPtr (paddr)->type = PG_GHOST;


  /*
   * Mark the physical page frames used to map the entry as Ghost Page Table
   * Pages.  Note that we don't mark the PML4E as a ghost page table page
   * because it is also used to map traditional memory pages (it is a top-most
   * level page table page).
   */
  getPageDescPtr (get_pdptePaddr (pml4e, vaddr))->ghostPTP = 1;
  getPageDescPtr (get_pdePaddr (pdpte, vaddr))->ghostPTP = 1;
  getPageDescPtr (get_ptePaddr (pde, vaddr))->ghostPTP = 1;
  return pml4eVal;
}

/*
 * Function: unmapSecurePage()
 *
 * Description:
 *  Unmap a single frame of secure memory from the specified virtual address.
 *
 * Inputs:
 *  vaddr - The virtual address to unmap.
 *
 * TODO:
 *  Implement code that will tell other processors to invalid their TLB entries
 *  for this page.
 */
void
unmapSecurePage (unsigned char * v) {
  /*
   * Get the PML4E of the current page table.  If there isn't one in the
   * table, add one.
   */
  uintptr_t vaddr = (uintptr_t) v;
  pml4e_t * pml4e = get_pml4eVaddr (get_pagetable(), vaddr);
  if (!isPresent (pml4e)) {
    panic ("SVA: unmapSecurePage: No PML4E!\n");
  }

  /*
   * Get the PDPTE entry (or add it if it is not present).
   */
  pdpte_t * pdpte = get_pdpteVaddr (pml4e, vaddr);
  if (!isPresent (pdpte)) {
    panic ("SVA: unmapSecurePage: No PDPTE!\n");
  }

  if ((*pdpte) & PTE_PS) {
    panic ("unmapSecurePage: PDPTE has PS BIT\n");
  }

  /*
   * Get the PDE entry (or add it if it is not present).
   */
  pde_t * pde = get_pdeVaddr (pdpte, vaddr);
  if (!isPresent (pde)) {
    panic ("SVA: unmapSecurePage: No PDE!\n");
  }

  if ((*pde) & PTE_PS) {
    panic ("unmapSecurePage: PDE has PS BIT\n");
  }

  /*
   * Get the PTE entry (or add it if it is not present).
   */
  pte_t * pte = get_pteVaddr (pde, vaddr);
  if (!isPresent (pte)) {
    panic ("SVA: unmapSecurePage: PTE is not present!\n");
  }

  /*
   * Modify the PTE so that the page is not present.
   */
  *pte = 0;

  /*
   * Invalidate any TLBs in the processor.
   */
  sva_mm_flush_tlb (v);

  /*
   * Go through and determine if any of the SVA VM pages tables are now unused.
   * If so, decrement their uses.
   *
   * The goal here is to make unused page tables have all unused entries so
   * that the operating system doesn't get confused.
   */
  unsigned int ptindex;
  if ((ptindex = releaseUse (pte))) {
    freePTPage (ptindex);
    *pde = 0;
    if ((ptindex = releaseUse (pde))) {
      freePTPage (ptindex);
      *pdpte = 0;
      if ((ptindex = releaseUse (pdpte))) {
        *pml4e = 0;
        freePTPage (ptindex);
        if ((ptindex = releaseUse (pml4e))) {
          freePTPage (ptindex);
        }
      }
    }
  }

  return;
}

#if 0
static unsigned int
is_l1_user_page (pte_t* virtual) {
  void* pagetable = get_pagetable();
  unsigned long pa;
  
  pte_t* pte = get_pte((unsigned long)virtual, pagetable);
  pa = pte_val(*pte) >> PAGE_SHIFT;
  return (page_desc[pa].l1_user);
}

static unsigned int
is_user_page (pte_t* virtual) {
  void* pagetable = get_pagetable();
  unsigned long pa;

  pte_t* pte = get_pte((unsigned long)virtual, pagetable);
  pa = pte_val(*pte) >> PAGE_SHIFT;
  return (page_desc[pa].user);
}

/*
 * Function: is_l1_kernel_page()
 *
 * Description:
 *  Determines whether the given virtual address points to memory that is used
 *  by an Level 1 page table page that maps memory into the kernel's reserved
 *  portion of the address space.
 *
 * Inputs:
 *  virtual - The virtual address to check.
 *
 * Return value:
 *  1 - The address points to memory used for an L1 page table.
 *  0 - The address does not point to memory used for an L1 page table.
 */
unsigned int
is_l1_kernel_page (pte_t* virtual) {
  void* pagetable = get_pagetable();
  unsigned long pa;

  pte_t* pte = get_pte((unsigned long)virtual, pagetable);
  pa = pte_val(*pte) >> PAGE_SHIFT;
  return (page_desc[pa].l1_kernel);
}


/*
 *****************************************************************************
 * SVA MMU Intrinsic Implementations
 *****************************************************************************
 */

/*
 * Called by the memory fault handler to check that the kernel did not try to
 * write into a pagetable directly.
 */
void llva_check_pagetable_write(unsigned long address, void* pagetable) {
  pte_t* pte = get_pte(address, pagetable);
  if (pte && page_desc) {
    pte_t val = *pte;
    unsigned long index = pte_val(val) >> PAGE_SHIFT; 
    if (likely(page_desc[index].l1 || page_desc[index].l2)) {
      poolcheckfail("MMU: The kernel tried to write directly on a pagetable: %x",
                    __builtin_return_address(0));
    }
  }
}

/*
 * Checks that the pagetable has correct flags and loads it.
 */
void llva_check_pagetable(pgd_t* pgd) {
  
  void* pagetable = get_pagetable();
  pte_t* pte = get_pte((unsigned long)pgd, pagetable);
  unsigned long index = pte_val(*pte) >> PAGE_SHIFT; 
  if (unlikely(!page_desc[index].l2)) {
    poolcheckfail("MMU: Try to load a non L2 page table: %x", 
                  __builtin_return_address(0));
  }
  
  __asm__ __volatile__ ("movl %0, %%cr3\n"
                        :
                        : "r" (__pa(pgd)));

  return;
}
#endif

/*
 * Intrinsic: sva_mm_load_pgtable()
 *
 * Description:
 *  Set the current page table.  This implementation will also enable paging.
 *
 * TODO:
 *  This should check that the page table points to an L1 page frame.
 */
void
sva_mm_load_pgtable (void * pg) {
  /*
   * Disable interrupts so that we appear to execute as a single instruction.
   */
  unsigned long rflags = sva_enter_critical();

  /* Control Register 0 Value (which is used to enable paging) */
  unsigned int cr0;

#if DEBUG >= 5
  printf("##### SVA<sva_mm_load_pgtable> new entry value: 0x%lx,", pg);
  print_regs();
#endif 

  /* 
   * Unset page protection so that we can write to cr3 and can write into
   * the top-level page-table page if necessary.
   */
  unprotect_paging();

  /*
   * Load the new page table and enable paging in the CR0 register.
   */
  __asm__ __volatile__ ("movq %1, %%cr3\n"
                        "movl %%cr0, %0\n"
                        "orl  $0x80000000, %0\n"
                        "movl %0, %%cr0\n"
                        : "=r" (cr0)
          : "r" (pg) : "memory");
    
#if DEBUG >= 5
  print_regs();
#endif

  /*
   * Ensure that the secure memory region is still mapped within the current
   * set of page tables.
   */
  struct SVAThread * threadp = getCPUState()->currentThread;
  if (threadp->secmemSize) {
    /*
     * Get a pointer into the page tables for the secure memory region.
     */
    pml4e_t * secmemp = (pml4e_t *) getVirtual (get_pagetable() + secmemOffset);

    /*
     * Restore the PML4E entry for the secure memory region.
     */
    *secmemp = threadp->secmemPML4e;
  }

  /*
   * Mark the page table pages as read-only again.
   */
  protect_paging();

  /* Restore interrupts */
  sva_exit_critical (rflags);

  return;
}

/*
 * Function: sva_load_cr0
 *
 * Description:
 *  SVA Intrinsic to load the cr0 value. We need to make sure write protection
 *  is enabled. 
 */
void 
sva_load_cr0 (unsigned long val) {
#if ACTIVATE_PROT
    val |= CR0_WP;
#endif 
    _load_cr0(val);
}

/*
 * Function: declare_ptp_and_walk_pt_entries
 *
 * Descriptions:
 *  This function recursively walks a page table and it's entries to initalize
 *  the SVA data structures for the given page. This function is meant to
 *  initialize SVA data structures so they mirror the static page table setup
 *  by a kernel. However, it uses the paging structure itself to walk the
 *  pages, which means it should be agnostic to the operating system being
 *  employed upon. The function only walks into page table pages that are valid
 *  or enabled. It also makes sure that if a given page table is already active
 *  in SVA then it skips over initializing its entries as that could cause an
 *  infinite loop of recursion. This is an issue in FreeBSD as they have a
 *  recursive mapping in the pml4 top level page table page.
 *  
 *  If a given page entry is marked as having a larger page size, such as may
 *  be the case with a 2MB page size for PD entries, then it doesn't traverse
 *  the page. Therefore, if the kernel page tables are configured correctly
 *  this won't initialize any SVA page descriptors that aren't in use.
 *
 *  The primary objective of this code is to for each valid page table page:
 *      [1] Initialize the page_desc for the given page
 *      [2] Set the page permissions as read only
 *
 * Assumptions:
 *  - The number of entries per page assumes a amd64 paging hardware mechanism.
 *    As such the number of entires per a 4KB page table page is 2^9 or 512
 *    entries. 
 *  - This page referenced in pageMapping has already been determined to be
 *    valid and requires SVA metadata to be created.
 *
 * Inputs:
 *   pageMapping: Page mapping associated with the given page being traversed.
 *                This mapping identifies the physical address/frame of the
 *                page table page so that SVA can initialize it's data
 *                structures then recurse on each entry in the page table page. 
 *  numPgEntries: The number of entries for a given level page table. 
 *     pageLevel: The page level of the given mapping {1,2,3,4}.
 *
 *
 * TODO: 
 *  - Modify the page entry number to be dynamic in some way to accomodate
 *    differing numbers of entries. This only impacts how we traverse the
 *    address structures. The key issue is that we don't want to traverse an
 *    entry that randomly has the valid bit set, but not have it point to a
 *    real page. For example, if the kernel did not zero out the entire page
 *    table page and only inserted a subset of entries in the page table, the
 *    non set entries could be identified as holding valid mappings, which
 *    would then cause this function to traverse down truly invalid page table
 *    pages. In FreeBSD this isn't an issue given the way they initialize the
 *    static mapping, but could be a problem given differnet intialization
 *    methods.
 *
 */
#define DEBUG_INIT 0
void 
declare_ptp_and_walk_pt_entries(page_entry_t *pageEntry, unsigned long
        numPgEntries, enum page_type_t pageLevel ) 
{ 
  int i;
  int traversedPTEAlready;
  enum page_type_t subLevelPgType;
  unsigned long numSubLevelPgEntries;
  page_desc_t *thisPg;
  page_entry_t pageMapping; 
  page_entry_t *pagePtr;

  /* Store the pte value for the page being traversed */
  pageMapping = *pageEntry;

  /* Set the page pointer for the given page */
#if USE_VIRT
  uintptr_t pagePhysAddr = pageMapping & PG_FRAME;
  pagePtr = (page_entry_t *) getVirtual(pagePhysAddr);
#else
  pagePtr = (uintptr_t)(pageMapping & PG_FRAME);
#endif

  /* Get the page_desc for this page */
  thisPg = getPageDescPtr(pageMapping);

  /* Mark if we have seen this traversal already */
  traversedPTEAlready = (thisPg->type != PG_UNUSED);

#if DEBUG_INIT >= 1
  /* Character inputs to make the printing pretty for debugging */
  char * indent = "";
  char * l4s = "L4:";
  char * l3s = "\tL3:";
  char * l2s = "\t\tL2:";
  char * l1s = "\t\t\tL1:";

  switch (pageLevel){
    case PG_L4:
        indent = l4s;
        printf("%sSetting L4 Page: mapping:0x%lx\n", indent, pageMapping);
        break;
    case PG_L3:
        indent = l3s;
        printf("%sSetting L3 Page: mapping:0x%lx\n", indent, pageMapping);
        break;
    case PG_L2:
        indent = l2s;
        printf("%sSetting L2 Page: mapping:0x%lx\n", indent, pageMapping);
        break;
    case PG_L1:
        indent = l1s;
        printf("%sSetting L1 Page: mapping:0x%lx\n", indent, pageMapping);
        break;
    default:
        break;
  }
#endif

  /*
   * For each level of page we do the following:
   *  - Set the page descriptor type for this page table page
   *  - Set the sub level page type and the number of entries for the
   *    recursive call to the function.
   */
  switch(pageLevel){

    case PG_L4:

      thisPg->type = PG_L4;       /* Set the page type to L4 */
      thisPg->user = 0;           /* Set the priv flag to kernel */
      ++(thisPg->count);
      subLevelPgType = PG_L3;
      numSubLevelPgEntries = NPML4EPG;//    numPgEntries;
      break;

    case PG_L3:
      
      thisPg->type = PG_L3;       /* Set the page type to L3 */
      thisPg->user = 0;           /* Set the priv flag to kernel */
      ++(thisPg->count);
      subLevelPgType = PG_L2;
      numSubLevelPgEntries = NPDPEPG; //numPgEntries;
      break;

    case PG_L2:
      
      /* 
       * If my L2 page mapping signifies that this mapping references a 1GB
       * page frame, then get the frame address using the correct page mask
       * for a L3 page entry and initialize the page_desc for this entry.
       * Then return as we don't need to traverse frame pages.
       */
      if ((pageMapping & PG_PS) != 0) {
#if DEBUG_INIT >= 1
        printf("\tIdentified 1GB page...\n");
#endif
        unsigned long index = (pageMapping & ~PDPMASK) / pageSize;
        page_desc[index].type = PG_TKDATA;
        page_desc[index].user = 0;           /* Set the priv flag to kernel */
        ++(page_desc[index].count);
        return;
      } else {
        thisPg->type = PG_L2;       /* Set the page type to L2 */
        thisPg->user = 0;           /* Set the priv flag to kernel */
        ++(thisPg->count);
        subLevelPgType = PG_L1;
        numSubLevelPgEntries = NPDEPG; // numPgEntries;
      }
      break;

    case PG_L1:
      /* 
       * If my L1 page mapping signifies that this mapping references a 2MB
       * page frame, then get the frame address using the correct page mask
       * for a L2 page entry and initialize the page_desc for this entry. 
       * Then return as we don't need to traverse frame pages.
       */
      if ((pageMapping & PG_PS) != 0){
#if DEBUG_INIT >= 1
        printf("\tIdentified 2MB page...\n");
#endif
        /* The frame address referencing the page obtained */
        unsigned long index = (pageMapping & ~PDRMASK) / pageSize;
        page_desc[index].type = PG_TKDATA;
        page_desc[index].user = 0;           /* Set the priv flag to kernel */
        ++(page_desc[index].count);
        return;
      } else {
        thisPg->type = PG_L1;       /* Set the page type to L1 */
        thisPg->user = 0;           /* Set the priv flag to kernel */
        ++(thisPg->count);
        subLevelPgType = PG_TKDATA;
        numSubLevelPgEntries = NPTEPG;//      numPgEntries;
      }
      break;

    default:
      printf("SVA: page type %d. Frame addr: %p\n",thisPg->type, pagePtr); 
      panic("SVA: walked an entry with invalid page type.");
  }
  
  /* 
   * There is one recursive mapping, which is the last entry in the PML4 page
   * table page. Thus we return before traversing the descriptor again.
   * Notice though that we keep the last assignment to the page as the page
   * type information. 
   */
  if(traversedPTEAlready) {
#if DEBUG_INIT >= 1
    printf("%sRecursed on already initialized page_desc\n", indent);
#endif
    return;
  }


#if 0//ACTIVATE_PROT

#if DEBUG_INIT
  printf("%sPre-WP :\t pageEntryPTR: %p, pageEntryVal: 0x%lx\n", indent,
          pageEntry, *pageEntry);
#endif

  /*
   * Given a valid and active entry set the read only bit for the
   * mapping before traversing the page table page. 
   */
#if 0
  unprotect_paging();
#endif
  page_entry_t readOnlyMapping = setMappingReadOnly(*pageEntry);
  page_entry_store(pageEntry, readOnlyMapping);             
#if 0
  printf("==== cr0: 0x%lx\n", _rcr0());
  protect_paging();
  printf("==== cr0: 0x%lx\n", _rcr0());
#endif

#if DEBUG_INIT
  printf("%sPost-WP:\t pageEntryPTR: %p, pageEntryVal: 0x%lx\n", indent,
          pageEntry, *pageEntry);
#endif

#endif /* ACTIVATE_PROT */
  
#if DEBUG_INIT >= 1
  u_long nNonValPgs=0;
  u_long nValPgs=0;
#endif
  /* 
   * Iterate through all the entries of this page, recursively calling the
   * walk on all sub entries.
   */
  for (i = 0; i < numSubLevelPgEntries; i++){
    /*
     * Do not process any entries that implement the direct map.  This prevents
     * us from marking physical pages in the direct map as kernel data pages.
     */
    if ((pageLevel == PG_L4) && (i == (0xfffffe0000000000 / 0x1000))) {
      continue;
    }
#if OBSOLETE
    //pagePtr += (sizeof(page_entry_t) * i);
    //page_entry_t *nextEntry = pagePtr;
#endif
    page_entry_t * nextEntry = & pagePtr[i];

#if DEBUG_INIT >= 5
    printf("%sPagePtr in loop: %p, val: 0x%lx\n", indent, nextEntry, *nextEntry);
#endif

    /* 
     * If this entry is valid then recurse the page pointed to by this page
     * table entry.
     */
    if (*nextEntry & PG_V) {
#if DEBUG_INIT >= 1
      nValPgs++;
#endif 

      /* 
       * If we hit the level 1 pages we have hit our boundary condition for
       * the recursive page table traversals. Now we just mark the leaf page
       * descriptors.
       */
      if (pageLevel == PG_L1){
#if DEBUG_INIT >= 2
          printf("%sInitializing leaf entry: pteaddr: %p, mapping: 0x%lx\n",
                  indent, nextEntry, *nextEntry);
#endif
      } else {
#if DEBUG_INIT >= 2
      printf("%sProcessing:pte addr: %p, newPgAddr: %p, mapping: 0x%lx\n",
              indent, nextEntry, (*nextEntry & PG_FRAME), *nextEntry ); 
#endif
          declare_ptp_and_walk_pt_entries(nextEntry,
                  numSubLevelPgEntries, subLevelPgType); 
      }
    } 
#if DEBUG_INIT >= 1
    else {
      nNonValPgs++;
    }
#endif
  }

#if DEBUG_INIT >= 1
  SVA_ASSERT((nNonValPgs + nValPgs) == 512, "Wrong number of entries traversed");

  printf("%sThe number of || non valid pages: %lu || valid pages: %lu\n",
          indent, nNonValPgs, nValPgs);
#endif

}

/*
 * Function declare_kernel_code_pages 
 *
 * Description: Mark all kernel code pages as code pages
 *
 * Inputs: 
 *  - btext : marks the beginning of the text segment
 *  - etext : marks the address of the end of the text segment
 */
void
declare_kernel_code_pages (uintptr_t btext, uintptr_t etext) {
    /* Get pointers for the pages */
    uintptr_t page;
    uintptr_t btextPage = btext & PG_FRAME;
    uintptr_t etextPage = etext & PG_FRAME;

    for (page = btextPage; page < etextPage; ) {
        /* Get the page frame index and get the codePg to mark */
        unsigned long index = page / pageSize;
        page_desc_t codePg = page_desc[index];

#if 0//ACTIVATE_PROT
        /* Set the code page to read only */
        page_entry_t romapping = setMappingReadOnly( * (page_entry_t *) page);
        printf("code page addr: %p, prev val: 0x%lx, new val: 0x%lx\n",
                page, *(page_entry_t *)page, romapping);
        panic("");
        /* SVA-TODO Get the pte for this kernel page */
        //page_entry_store((page_entry_t *)page, romapping);             
#endif

        /* Mark the page as both a code page and kernel level */
        codePg.type = PG_CODE; 
        codePg.user = 0;

        /* Set page to address of the next page */
        page += pageSize;
    }
}

/*
 * Function: sva_mmu_init
 *
 * Description:
 *  This function initializes the sva mmu unit by zeroing out the page
 *  descriptors, capturing the statically allocated initial kernel mmu state,
 *  and identifying all kernel code pages, and setting them in the page
 *  descriptor array.
 *
 *  To initialize the sva page descriptors, this function takes the pml4 base
 *  mapping and walks down each level of the page table tree. 
 *
 *  NOTE: In this function we assume that he page mapping for the kpml4 has
 *  physical addresses in it. We then dereference by obtaining the virtual
 *  address mapping of this page. This works whether or not the processor is in
 *  a virtually addressed or physically addressed mode. 
 *
 * Inputs:
 *  - kpml4Mapping  : Mapping referencing the base kernel pml4 page table page
 *  - nkpml4e       : The number of entries in the pml4
 */
void 
sva_mmu_init(pml4e_t * kpml4Mapping, unsigned long nkpml4e, uintptr_t btext,
        uintptr_t etext)
{
    /* Get the virtual address of the pml4e mapping */
#if USE_VIRT
    pml4e_t * kpml4eVA = (pml4e_t *) getVirtual( (uintptr_t) kpml4Mapping);
#else
    pml4e_t * kpml4eVA = kpml4Mapping;
#endif

    /* Zero out the page descriptor array */
    memset (page_desc, 0, numPageDescEntries * sizeof(page_desc_t));

    /* Walk the kernel page tables and initialize the sva page_desc */
    declare_ptp_and_walk_pt_entries(kpml4eVA, nkpml4e, PG_L4);
    
    /* TODO: Set page_desc pages as SVA pages */

    /* TODO: Set the SVA pages as read only */
    
    /* Identify kernel code pages and intialize the descriptors */
    declare_kernel_code_pages(btext, etext);
    
    /* Now load the initial value of the cr3 to complete kernel init */
    load_cr3(*kpml4Mapping & PG_FRAME);

#if 0//ACTIVATE_PROT
    u_long sp;
    __asm __volatile("movq %%rsp,%0" : "=r" (sp));
    printf("<<<< cpu_setregs: the stack pointer: %p\n",sp);

    __asm __volatile("movq %%rbp,%0" : "=r" (sp));
    printf("<<<< cpu_setregs: the base pointer: %p\n",sp);

    /* Enable page protection */
    printf("==== cr0: 0x%lx\n", _rcr0());
    protect_paging();
    printf("==== cr0: 0x%lx\n", _rcr0());
    __asm __volatile("int $3");
    __asm __volatile("push %rsp");
    printf("==== cr0: 0x%lx\n", _rcr0());
    printf("Do we make it here?");
#endif

}

/*
 * Intrinsic: sva_declare_l1_page()
 *
 * Description:
 *  This intrinsic marks the specified physical frame as a Level 1 page table
 *  frame.  It will zero out the contents of the page frame so that stale
 *  mappings within the frame are not used by the MMU.
 *
 * Inputs:
 *  frameAddr - The address of the physical page frame that will be used as a
 *              Level 1 page frame.
 */
void
sva_declare_l1_page (uintptr_t frameAddr) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /* Get the page_desc for the newly declared l4 page frame */
  page_desc_t *pgDesc = getPageDescPtr(frameAddr);

  /*
   * Make sure that this is already an L1 page, an unused page, or a kernel
   * data page.
   */
  switch (pgDesc->type) {
    case PG_UNUSED:
    case PG_L1:
    case PG_TKDATA:
      break;

    default:
      printf ("SVA: %lx %lx\n", page_desc, page_desc + numPageDescEntries);
      panic ("SVA: Declaring L1 for wrong page: frameAddr = %lx, pgDesc=%lx, type=%x\n", frameAddr, pgDesc, pgDesc->type);
      break;
  }

  /*
   * Mark this page frame as an L1 page frame.
   */
  pgDesc->type = PG_L1;

  /* 
   * Initialize the page data and page entry. Note that we pass a general
   * page_entry_t to the function as it enables reuse of code for each of the
   * entry declaration functions. 
   */
  init_page_entry(frameAddr);

  /* Restore interrupts */
  sva_exit_critical (rflags);
}

/*
 * Intrinsic: sva_declare_l2_page()
 *
 * Description:
 *  This intrinsic marks the specified physical frame as a Level 2 page table
 *  frame.  It will zero out the contents of the page frame so that stale
 *  mappings within the frame are not used by the MMU.
 *
 * Inputs:
 *  frameAddr - The address of the physical page frame that will be used as a
 *              Level 2 page frame.
 */
void
sva_declare_l2_page (uintptr_t frameAddr) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /* Get the page_desc for the newly declared l4 page frame */
  page_desc_t *pgDesc = getPageDescPtr(frameAddr);

  /*
   * Make sure that this is already an L2 page, an unused page, or a kernel
   * data page.
   */
  switch (pgDesc->type) {
    case PG_UNUSED:
    case PG_L2:
    case PG_TKDATA:
      break;

    default:
      printf ("SVA: %lx %lx\n", page_desc, page_desc + numPageDescEntries);
      panic ("SVA: Declaring L2 for wrong page: frameAddr = %lx, pgDesc=%lx, type=%x\n", frameAddr, pgDesc, pgDesc->type);
      break;
  }

  /* Setup metadata tracking for this new page */
  pgDesc->type = PG_L2;

  /* 
   * Initialize the page data and page entry. Note that we pass a general
   * page_entry_t to the function as it enables reuse of code for each of the
   * entry declaration functions. 
   */
  init_page_entry(frameAddr);

  /* Restore interrupts */
  sva_exit_critical (rflags);
  return;
}

/*
 * Intrinsic: sva_declare_l3_page()
 *
 * Description:
 *  This intrinsic marks the specified physical frame as a Level 3 page table
 *  frame.  It will zero out the contents of the page frame so that stale
 *  mappings within the frame are not used by the MMU.
 *
 * Inputs:
 *  frameAddr - The address of the physical page frame that will be used as a
 *              Level 3 page frame.
 */
void
sva_declare_l3_page (uintptr_t frameAddr) {
  /* Disable interrupts so that we appear to execute as a single instruction */
  unsigned long rflags = sva_enter_critical();

  /* Get the page_desc for the newly declared l4 page frame */
  page_desc_t *pgDesc = getPageDescPtr(frameAddr);

  /*
   * Make sure that this is already an L3 page, an unused page, or a kernel
   * data page.
   */
  switch (pgDesc->type) {
    case PG_UNUSED:
    case PG_L3:
    case PG_TKDATA:
      break;

    default:
      printf ("SVA: %lx %lx\n", page_desc, page_desc + numPageDescEntries);
      panic ("SVA: Declaring L3 for wrong page: frameAddr = %lx, pgDesc=%lx, type=%x\n", frameAddr, pgDesc, pgDesc->type);
      break;
  }

  /* Mark this page frame as an L3 page frame */
  pgDesc->type = PG_L3;

  /* 
   * Initialize the page data and page entry. Note that we pass a general
   * page_entry_t to the function as it enables reuse of code for each of the
   * entry declaration functions. 
   */
  init_page_entry(frameAddr);

  /* Restore interrupts */
  sva_exit_critical (rflags);
  return;
}

/*
 * Intrinsic: sva_declare_l4_page()
 *
 * Description:
 *  This intrinsic marks the specified physical frame as a Level 4 page table
 *  frame.  It will zero out the contents of the page frame so that stale
 *  mappings within the frame are not used by the MMU.
 *
 * Inputs:
 *  frameAddr - The address of the physical page frame that will be used as a
 *              Level 4 page frame.
 */
void
sva_declare_l4_page (uintptr_t frameAddr) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /* Get the page_desc for the newly declared l4 page frame */
  page_desc_t *pgDesc = getPageDescPtr(frameAddr);

  /* 
   * Assert that this is a new L4. We don't want to declare an L4 with and
   * existing mapping
   */
#if 0
  SVA_ASSERT(pgRefCount(pgDesc) == 0, "MMU: L4 reference count non-zero.");
#endif

  /*
   * Make sure that this is already an L4 page, an unused page, or a kernel
   * data page.
   */
  switch (pgDesc->type) {
    case PG_UNUSED:
    case PG_L4:
    case PG_TKDATA:
      break;

    default:
      printf ("SVA: %lx %lx\n", page_desc, page_desc + numPageDescEntries);
      panic ("SVA: Declaring L4 for wrong page: frameAddr = %lx, pgDesc=%lx, type=%x\n", frameAddr, pgDesc, pgDesc->type);
      break;
  }

  /* 
   * We need to make sure that this page is not being used for some other
   * purpose which would prevent it from being used as a page table page.
   * Check for that before modifying the page.
   */
  if (canBeDeclared(pgDesc)) {
    /* Mark this page frame as an L4 page frame */
    pgDesc->type = PG_L4;

    /* 
     * Initialize the page data and page entry. Note that we pass a general
     * page_entry_t to the function as it enables reuse of code for each of the
     * entry declaration functions. 
     */
    init_page_entry(frameAddr);
  }

  /* Restore interrupts */
  sva_exit_critical (rflags);
}

/*
 * Function: sva_remove_page()
 *
 * Description:
 *  This function informs the SVA VM that the system software no longer wants
 *  to use the specified page as a page table page.
 *
 * Inputs:
 *  paddr - The physical address of the page table page.
 */
void
sva_remove_page (uintptr_t paddr) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /* Get the entry controlling the permissions for this pte PTP */
  page_entry_t *pte = get_pgeVaddr(getVirtual (paddr));

  /* Get the page_desc for the l1 page frame */
  page_desc_t *pgDesc = getPageDescPtr(paddr);

  /*
   * Make sure that this is an L1 page.  We don't want the system software to
   * trick us.
   */
  switch (pgDesc->type)  {
    case PG_L1:
    case PG_L2:
    case PG_L3:
    case PG_L4:
      break;

    default:
      panic ("SVA: undeclare bad page type: %lx %lx\n", paddr, pgDesc->type);
      break;
  }

  /*
   * Check that there are no references to this page (i.e., there is no page
   * table entry that refers to this physical page frame).  If there is a
   * mapping, then someone is still using it as a page table page.  In that
   * case, ignore the request.
   */
  if (pgDesc->count == 0) {
    /*
     * Mark the page frame as an unused page.
     */
    pgDesc->type = PG_UNUSED;

    /*
     * Make the page writeable again.
     */
    __update_mapping (pte, setMappingReadWrite (*pte));
  }

  /* Restore interrupts */
  sva_exit_critical (rflags);
  return;
}

#if 0
/*
 * Called by the memory intialisation process of the kernel once the
 * bootstrap pagetable is populated. 
 * 
 * This function sets the corresponding flags for pagetable pages 
 * (level2 for the root pagetable, level1 for the pages it references),
 * and sets these pages as read-only.
 * 
 * It also puts the kernel/sva code pages as read-only.
 */

void llva_end_mem_init(pgd_t * pgdptr, unsigned long max_pfn, 
                       alloc_boot_t allocator) {
  unsigned long codesize = &_etext - &_text;
  unsigned long i = 0, j = 0;
  void* pagetable = pgdptr;

  /* (1) Allocate the page_desc array */
  unsigned long desc_size = max_pfn * sizeof(page_desc_t);
  /*desc_size = desc_size + X86_PAGE_SIZE - (desc_size % X86_PAGE_SIZE);*/
  page_desc = (page_desc_t*)allocator(desc_size);
  memset(page_desc, 0, desc_size);
  /* Set the page_desc as sva pages */
  for (i = (unsigned)page_desc/X86_PAGE_SIZE; 
       i < ((unsigned)page_desc + desc_size)/X86_PAGE_SIZE; 
       ++i) {
    pte_t* pte = get_pte(i, pagetable);
    unsigned long page_index = pte_val(*pte) >> PAGE_SHIFT;
    page_desc[page_index].sva = 1;
  }

  /* (2) Set the root pagetable as read-only and level2 page */
  pte_t* pte = get_pte((unsigned long)pgdptr, pagetable);
  pte_t new_val = __pte(pte_val(*pte) & ~_PAGE_RW);
  unsigned long index = pte_val(new_val) >> PAGE_SHIFT;
  page_desc[index].l2 = 1;
 
  unsigned eflags;
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));
  unprotect_paging();
  (*pte) = new_val;
  
  /* (3) Make page table pages read only, and set the level1 flag */
  for (i = 0; i < PTRS_PER_PGD; i++) {
    if (!pmd_none(__pmd(pgd_val(pgdptr[i])))) {
      unsigned long tmp = pmd_page(((pmd_t*)pgdptr)[i]);
      pte = get_pte((unsigned long)tmp, pagetable);
      index = pte_val(*pte) >> PAGE_SHIFT;
      page_desc[index].l1 = 1;
      page_desc[index].l1_count = 1;
      page_desc[index].l1_kernel = 1;
      (*pte) = __pte(pte_val(*pte) & ~_PAGE_RW);
      /*
      for (j = 0; j < PTRS_PER_PTE; j++) {
        unsigned long val = pte_val(((pte_t*)tmp)[i]);
        if (val) page_desc[val].count = 1;
      }*/
    }
  }

  /* (4) Set the kernel/sva code pages as read-only */

  /* Verify that _text is page aligned */
  if (!(((unsigned long)&_text) % X86_PAGE_SIZE == 0)) {
    poolcheckfail("MMU: _text is not page aligned %x", __builtin_return_address(0));
  }

  /* Set code pages as read-only */
  for (i = (unsigned long) &_text; i < codesize; i += X86_PAGE_SIZE) {
    pte_t* pte = get_pte(i, pagetable);
    (*pte) = __pte(pte_val((*pte)) & ~_PAGE_RW);
    unsigned long page_index = pte_val(*pte) >> PAGE_SHIFT;
    page_desc[page_index].code = 1;
  }

  //protect_paging();
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
}

#endif

/* 
 * Function: sva_update_mapping()
 *
 * Description:
 *  This function updates the entry to the page table page, and is agnostic to
 *  the level of page table. The particular needs for each page table level are
 *  handled in the __update_mapping function.
 *
 * Inputs:
 *  pteptr - The location within the page tabel page in which the new
 *           translation should be placed.
 *  val    - The new translation to insert into the page table.
 */
void
sva_update_mapping(page_entry_t * pteptr, page_entry_t val) {
    __update_mapping(pteptr,val);
}

/* 
 * Function: sva_remove_mapping()
 *
 * Description:
 *  This function updates the entry to the page table page and is agnostic to
 *  the level of page table. The particular needs for each page table level are
 *  handled in the __update_mapping function. The primary function here is to
 *  set the mapping to zero, if the page was a PTP then zero it's data and set
 *  it to writeable.
 *
 * Inputs:
 *  pteptr - The location within the page table page for which the translation
 *           should be removed.
 */
void
sva_remove_mapping(page_entry_t * pteptr) {
  /* Disable interrupts so that we appear to execute as a single instruction. */
  unsigned long rflags = sva_enter_critical();

  /* Get the page_desc for the newly declared l4 page frame */
  page_desc_t *pgDesc = getPageDescPtr(*pteptr);

  /* Update the page table mapping to zero */
  __update_mapping(pteptr, ZERO_MAPPING);

  /* 
   * If the page is a read only type then we need to zero it and mark it as
   * writeable again. This function also releases the virtual ghost data
   * structures for the page. 
   */
  if (readOnlyPageType(pgDesc)) {
    __clean_and_restore_ptp (pteptr);
  }

  /* Restore interrupts */
  sva_exit_critical (rflags);
}

/* 
 * Function: sva_update_l1_mapping()
 *
 * Description:
 *  This function updates a Level-1 Mapping.  In other words, it adds a
 *  a direct translation from a virtual page to a physical page.
 *
 *  This function makes different checks to ensure the mapping
 *  does not bypass the type safety proved by the compiler.
 *
 * Inputs:
 *  pteptr - The location within the L1 page in which the new translation
 *           should be place.
 *  val    - The new translation to insert into the page table.
 */
void
sva_update_l1_mapping(pte_t * pteptr, page_entry_t val) {
  /*
   * Disable interrupts so that we appear to execute as a single instruction.
   */
  unsigned long rflags = sva_enter_critical();

  /*
   * Ensure that the PTE pointer points to an L1 page table.  If it does not,
   * then report an error.
   */
  page_desc_t * ptDesc = getPageDescPtr (getPhysicalAddr (pteptr));
  if (ptDesc->type != PG_L1) {
    panic ("SVA: MMU: update_l1 not an L1: %lx %lx: %lx\n", pteptr, val, ptDesc->type);
  }

  /*
   * Update the page table with the new mapping.
   */
  __update_mapping(pteptr, val);

  /* Restore interrupts */
  sva_exit_critical (rflags);
  return;
}

/*
 * Updates a level2 mapping (a mapping to a l1 page).
 *
 * This function checks that the pages involved in the mapping
 * are correct, ie pmdptr is a level2, and val corresponds to
 * a level1.
 */
void
sva_update_l2_mapping(pde_t * pdePtr, page_entry_t val) {
  /*
   * Disable interrupts so that we appear to execute as a single instruction.
   */
  unsigned long rflags = sva_enter_critical();

#if 1
  /*
   * Ensure that the PTE pointer points to an L1 page table.  If it does not,
   * then report an error.
   */
  page_desc_t * ptDesc = getPageDescPtr (getPhysicalAddr (pdePtr));
  if (ptDesc->type != PG_L2) {
    printf ("SVA: MMU: update_l2 not an L2: %lx %lx: type=%lx count=%lx\n", pdePtr, val, ptDesc->type, ptDesc->count);
  }
#endif

  /*
   * Update the page mapping.
   */
  __update_mapping(pdePtr, val);

#if OBSOLETE
    void* pagetable = get_pagetable();

    if (pmd_val(val)) {
        pte_t* pte = get_pte((unsigned long)pmdptr, pagetable);

        /* Verify that pmdptr points to a level2 page */
        unsigned long index = pte_val(*pte) >> PAGE_SHIFT;
        if (unlikely(!page_desc[index].l2)) {
            poolcheckfail("MMU: Try to put a L1 in a non-L: %x", __builtin_return_address(0));
        }


        /* Verify that val contains a level1 page */
        unsigned long addr = pmd_page(val);
        pte_t* l1 = get_pte(addr, pagetable);
        index = pte_val(*l1) >> PAGE_SHIFT;
        if (unlikely(!page_desc[index].l1)) {
            poolcheckfail("MMU: Try to put a non-L1 in a L2: %x", __builtin_return_address(0));
        } else {
            if (page_desc[index].l1_count < ((1 << 5) - 1)) {
                page_desc[index].l1_count++;
            } else
                poolcheckfail("MMU: Overflow in the L1 count: %x", __builtin_return_address(0));
        }

        /*
         * Determine if the L1 page will be mapping values into user-space virtual
         * address or kernel-space virtual address.  We do this by finding the
         * offset from the beginning of the page table (which is the address of
         * where the translation is to be stored rounded down to the nearest page;
         * this works because the page global directory can only be a single page
         * in length).
         */
        unsigned int pmdbase = ((unsigned)(pmdptr)) & PAGE_MASK;
        if (pmdptr < (((pgd_t*)pmdbase) + USER_PTRS_PER_PGD))
            page_desc[index].l1_user = 1;
        else
            page_desc[index].l1_kernel = 1;
    } 

    if (pmd_val(*pmdptr)) {
        unsigned long old_addr = pmd_page(*pmdptr);
        pte_t* old_pte = get_pte(old_addr, pagetable);
        unsigned long old_index = pte_val(*old_pte) >> PAGE_SHIFT;
        /** NDD NOTE
         * This effectively makes sure that this page was an l1, we ensure
         * insertion will be correct, therefore don't need to explicitly verify
         * this.
         */
        if (page_desc[old_index].l1_count <= 0)
            poolcheckfail("MMU: Page in L1 was not a L1: %x!", __builtin_return_address(0));

        page_desc[old_index].l1_count--;
    }
#endif

  /* Restore interrupts */
  sva_exit_critical (rflags);
  return;
}

/*
 * Updates a level3 mapping 
 */
void sva_update_l3_mapping(pdpte_t * pdptePtr, page_entry_t val) {
  /*
   * Disable interrupts so that we appear to execute as a single instruction.
   */
  unsigned long rflags = sva_enter_critical();

  /*
   * Ensure that the PTE pointer points to an L1 page table.  If it does not,
   * then report an error.
   */
  page_desc_t * ptDesc = getPageDescPtr (getPhysicalAddr (pdptePtr));
  if (ptDesc->type != PG_L3) {
    panic ("SVA: MMU: update_l3 not an L3: %lx %lx: %lx\n", pdptePtr, val, ptDesc->type);
  }

  __update_mapping(pdptePtr, val);

  /* Restore interrupts */
  sva_exit_critical (rflags);
  return;
}

/*
 * Updates a level4 mapping 
 */
void sva_update_l4_mapping (pml4e_t * pml4ePtr, page_entry_t val) {
  /*
   * Disable interrupts so that we appear to execute as a single instruction.
   */
  unsigned long rflags = sva_enter_critical();

  /*
   * Ensure that the PTE pointer points to an L1 page table.  If it does not,
   * then report an error.
   */
  page_desc_t * ptDesc = getPageDescPtr (getPhysicalAddr (pml4ePtr));
  if (ptDesc->type != PG_L4) {
    panic ("SVA: MMU: update_l4 not an L4: %lx %lx: %lx\n", pml4ePtr, val, ptDesc->type);
  }

  __update_mapping(pml4ePtr, val);

  /* Restore interrupts */
  sva_exit_critical (rflags);
  return;
}

#if 0
/*
 * Intrinsic: sva_get_physical ()
 *
 * Description:
 *  Given a virtual address, convert it into its physical address.
 *
 * Inputs:
 *  virtual - The virtual address to convert.
 *
 * Return value:
 *  The physical address of the memory location to which v points is returned.
 *
 * Notes:
 *  This does not properly handle the case where the virtual page has no
 *  mapping at all.
 */
void *
sva_get_physical (void * virtual) {
  extern int pchk_ready;

  /*
   * Get the page table.
   */
  void* pagetable = get_pagetable();

  /*
   * Get the physical page associated with the virtual address.
   */
  pte_t* pte = get_pte((unsigned long)virtual, pagetable);
  unsigned long paddr = (pte_val(*pte) & PAGE_MASK);
  paddr += (((unsigned long)(virtual)) & 0x000000FFF);
  if (pchk_ready)
    printk ("LLVA: sva_get_physical: %x %x\n", virtual, paddr);
  return ((void *)(paddr));
}
#endif


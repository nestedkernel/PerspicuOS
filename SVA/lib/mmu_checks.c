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

#include "sva/mmu.h"

/*
 * Frame usage constants
 */
const unsigned char PG_UNUSED = 0x0;
const unsigned char PG_TKDATA = 0x1;
const unsigned char PG_TUDATA = 0x2;
const unsigned char PG_CODE   = 0x3;
const unsigned char PG_STACK  = 0x4;
const unsigned char PG_IO     = 0x5;
const unsigned char PG_SVA    = 0x6;
const unsigned char PG_L1     = 0x7;
const unsigned char PG_L2     = 0x8;
const unsigned char PG_L3     = 0x9;
const unsigned char PG_L4     = 0xA;

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
  unsigned char type;

  /* Number of times a page is mapped */
  unsigned count : 12;

  /* Number of times a page is used as a l1 page */
  unsigned l1_count : 5;

  /* Number of times a page is used as a l2 page (unused in non-PAE) */
  unsigned l2_count : 2;

  /* Is this page a L1 in user-space? */
  unsigned l1_user : 1;

  /* Is this page a L1 in kernel-space? */
  unsigned l1_kernel : 1;

  /* Is this page a user page? */
  unsigned user : 1;
} page_desc_t;

/* Size of the physical memory and page size in bytes */
const unsigned int memSize = 1024*1024*1024;
const unsigned int pageSize = 4096;

/* Array describing the physical pages */
/* The index is the physical page number */
static page_desc_t page_desc[memSize / 4096];

/* Flags bits in x86_64 PTE entries */
const unsigned PTE_PRESENT  = 0x0001u;
const unsigned PTE_CANWRITE = 0x0002u;
const unsigned PTE_CANUSER  = 0x0004u;
const unsigned PTE_PS       = 0x0080u;

/* Number of bits to shift to get the page number out of a PTE entry */
const unsigned PAGESHIFT = 12;

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
 *  Return a virtual address that can be used to access the current page table.
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
  return (getVirtual (cr3 & 0xfffffffffffff000u));
}

/*
 * Function: protect_pte()
 *
 * Description:
 *  Protects the page table entry. This disables the flag in CR0 which bypasses
 *  the RW flag in pagetables. After this call, it is safe to re-enable
 *  interrupts.
 */
static inline void
protect_pte(void) {
  /* The flag value for enabling page protection */
  const uintptr_t flag = 0x00010000;
  uintptr_t value = 0;
  __asm__ __volatile ("movq %%cr0,%0\n": "=r" (value));
  value |= flag;
  __asm__ __volatile ("movq %0,%%cr0\n": :"r" (value));
  return;
}

/*
 * Function: unprotect_pte
 *
 * Description:
 *  This function disables page protection on x86_64 systems.  It is used by
 *  the SVA VM to allow itself to disable protection to update the in-memory
 *  page tables.
 */
static inline void
unprotect_pte(void) {
  /* The flag value for enabling page protection */
  const uintptr_t flag = 0xfffffffffffeffff;
  uintptr_t value;
  __asm__ __volatile("movq %%cr0,%0\n": "=r"(value));
  value &= flag;
  __asm__ __volatile("movq %0,%%cr0\n": : "r"(value));
}

/*
 * Function: getPhysicalPage()
 *
 * Description:
 *  Find the physical page number of the specified virtual address.
 */
unsigned
getPhysicalPage (void * v) {
  extern int printf(const char *, ...);

  /*
   * Mask off the upper bits of the virtual address.  Part of it just isn't
   * used by the hardware.
   */
  uintptr_t vi = ((uintptr_t) v) & 0x0000ffffffffffffu;
  printf ("v   = %p\n", v);
  printf ("vi  = %lx\n", vi);

  /*
   * Get the currently active page table.
   */
  unsigned char * cr3 = get_pagetable();
  printf ("cr3 = %p\n", cr3);

  /*
   * Get the address of the PML4e.
   */
  unsigned char * p = (cr3 + ((vi >> 39) << 2));
  pml4e_t * pml4e = (pml4e_t *) getVirtual ((uintptr_t) p);
  pml4e = (pml4e_t *)((uintptr_t)(pml4e) & 0x000ffffffffff000u);
  printf ("pml4e  = %p\n", pml4e);
  printf ("pml4e  = %p %lx\n", pml4e, *pml4e);

  /*
   * Use the PML4E to get the address of the PDPTE.
   */
  vi &= 0x008fffffu;
  pml4e = (pml4e_t *)((uintptr_t)(pml4e) & 0x000ffffffffff000u);
  pdpte_t * pdpte = (pdpte_t *) getVirtual (*pml4e + ((vi  >> 30) << 2));

  printf ("vi     = %lx %lx\n", vi, vi >> 28);
  printf ("pdpte  = %p\n", pdpte);
#if 0
  printf ("pdpte  = %p %lx\n", pdpte, *pdpte);
#endif
  return 0;

#if 0
  /*
   * Go to the next level in the hierarchy.
   */
  l2_t * pde = 0;
  if ((*pdp) & PTE_PS) {
    return 0;
    /* return (pde[((vi >> 29u)) << 2] >> PAGESHIFT); */
  }

  /*
   * Go to the next level in the hierarchy.
   */
  pde = getVirtual (pdp[((vi >> 30) & 0x1ffu) << 2]);
  if (*pde & PTE_PS) {
    return 1;
  }

  l1_t * pte = getVirtual (pde[((vi >> 21) & 0x1ffu) << 2]);
  return (*pte >> PAGESHIFT);
#endif
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

#if 0
/*
 * Intrinsic: sva_declare_l1_page()
 *
 * Description:
 *  This intrinsic marks the specified physical frame as a Level 1 page table
 *  frame.  It will zero out the contents of the page frame so that stale
 *  mappings within the frame are not used by the MMU.
 *
 * Inputs:
 *  frame - The frame number of the physical page frame that will be used as a
 *          Level 1 page frame.
 */
void
sva_declare_l1_page (unsigned frame) {
  /*
   * Disable interrupts so that we appear to execute as a single instruction.
   */
  unsigned eflags;
  __asm__ __volatile__ ("pushf; popl %0; cli\n" : "=r" (eflags));

  /*
   * Mark this page frame as an L1 page frame.
   */
  page_desc[frame].type = PG_L1;

  /* The data contained in the page is set to 0 */
  memset (getVirtual (frame), 0, PAGE_SIZE);
 
  /* Update the page table entry with the new RO flag */ 
  unprotect_pte();
  (*pte) = new_val;
  protect_pte();
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
}
#endif

#if 0
/*
 * Removes the l1 flag of the page ands sets the page writable.
 */
void llva_remove_l1_page(pte_t * pteptr) {
  void* pagetable = get_pagetable();
  
  pte_t* pte = get_pte((unsigned long) pteptr, pagetable);
  pte_t new_val = __pte(pte_val(*pte) | _PAGE_RW);
  unsigned long index = pte_val(new_val) >> PAGE_SHIFT;

  if (page_desc[index].l1_count != 0) {
    poolcheckfail("MMU: removing an L1 page still referenced: %d %x",
                  page_desc[index].l1_count, __builtin_return_address(0));
  }

  page_desc[index].l1 = 0;
  page_desc[index].l1_user = 0;
  page_desc[index].l1_kernel = 0;

  unsigned eflags;
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));
  llva_unprotect_pte();
  (*pte) = new_val;
  llva_protect_pte();
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
}

/*
 * Sets a physical page as a level 2 page for pagetables.
 */
void llva_declare_l2_page(pgd_t * pgdptr) {

  void* pagetable = get_pagetable();

  memset(pgdptr, 0, USER_PTRS_PER_PGD * sizeof(pgd_t));
  memcpy(pgdptr + USER_PTRS_PER_PGD,
      swapper_pg_dir + USER_PTRS_PER_PGD,
      (PTRS_PER_PGD - USER_PTRS_PER_PGD) * sizeof(pgd_t));

  pte_t* pte = get_pte((unsigned long)pgdptr, pagetable);
  pte_t new_val = __pte(pte_val(*pte) & ~_PAGE_RW);
  unsigned long index = pte_val(new_val) >> PAGE_SHIFT;
  page_desc[index].l2 = 1;

  unsigned eflags;
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));
  llva_unprotect_pte();
  (*pte) = new_val;
  llva_protect_pte();
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
}

/*
 * Removes the l2 flag of the page and sets the page writable.
 */
void llva_remove_l2_page(pgd_t * pgdptr) {
  void* pagetable = get_pagetable();

  pte_t* pte = get_pte((unsigned long)pgdptr, pagetable);
  pte_t new_val = __pte(pte_val(*pte) | _PAGE_RW);
  unsigned long index = pte_val(new_val) >> PAGE_SHIFT;

  /*
   * Mark the page as no longer being a Level 2 (L2) page.
   */
  page_desc[index].l2 = 0;

  unsigned eflags;
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));

  /*
   * Make the page writeable again.
   */
  llva_unprotect_pte();
  (*pte) = new_val;
  llva_protect_pte();
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
}

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
  /*desc_size = desc_size + PAGE_SIZE - (desc_size % PAGE_SIZE);*/
  page_desc = (page_desc_t*)allocator(desc_size);
  memset(page_desc, 0, desc_size);
  /* Set the page_desc as sva pages */
  for (i = (unsigned)page_desc/PAGE_SIZE; 
       i < ((unsigned)page_desc + desc_size)/PAGE_SIZE; 
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
  llva_unprotect_pte();
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
  if (!(((unsigned long)&_text) % PAGE_SIZE == 0)) {
    poolcheckfail("MMU: _text is not page aligned %x", __builtin_return_address(0));
  }

  /* Set code pages as read-only */
  for (i = (unsigned long) &_text; i < codesize; i += PAGE_SIZE) {
    pte_t* pte = get_pte(i, pagetable);
    (*pte) = __pte(pte_val((*pte)) & ~_PAGE_RW);
    unsigned long page_index = pte_val(*pte) >> PAGE_SHIFT;
    page_desc[page_index].code = 1;
  }

  //llva_protect_pte();
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
}

/* 
 * Function: llva_update_l1_mapping()
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
 *  val    - The new translation to insert into the page table.  It has the
 *           format of an i386 PTE and contains the physical page and the
 *           configuration bits.
 */
void
llva_update_l1_mapping(pte_t* pteptr, pte_t val) {
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
    if (unlikely(page_desc[old_index].sva))
      poolcheckfail("MMU: try to modify the mapping of a sva page: %x", __builtin_return_address(0));
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

#if 0
  /*
   * If the new mapping makes the page available to user-space, record that.
   */
  if (((pte_val(val)) & PTE_CANUSER)) {
    page_desc[new_index].user = 1;
  } else {
    page_desc[new_index].kernel = 1;
  }
#endif
  
  /* Perform the pagetable mapping update */
  unsigned eflags;
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));
  llva_unprotect_pte();
  (*pteptr) = val;
  llva_protect_pte();
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
}

/*
 * Updates a level2 mapping (a mapping to a l1 page).
 *
 * This function checks that the pages involved in the mapping
 * are correct, ie pmdptr is a level2, and val corresponds to
 * a level1.
 */
void
llva_update_l2_mapping(pmd_t* pmdptr, pmd_t val) {
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
    if (page_desc[old_index].l1_count <= 0)
      poolcheckfail("MMU: Page in L1 was not a L1: %x!", __builtin_return_address(0));

    page_desc[old_index].l1_count--;
  }

  /* Perform the pagetable mapping update */
  unsigned eflags;
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));
  llva_unprotect_pte();
  *pmdptr = val;
  llva_protect_pte();
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
}

/*
 * Updates a level3 mapping (a mapping to a l2 page).
 */
void llva_update_l3_mapping(pgd_t* pgdptr, pgd_t val) {
  /* In x86, there are only 2 levels of pagetables. The level 3
   * is folded in the level 2. */
  llva_update_l2_mapping((pmd_t*)pgdptr, __pmd(pgd_val(val)));
}

/*
 * Empties the l1 entry and returns the old entry.
 */
pte_t llva_pte_get_and_clear(pte_t *xp) {
  pte_t val = *xp;
  llva_update_l1_mapping(xp, __pte(0));
  return val;
}

/*
 * Called by pchk_reg_obj to notify the MMU checking that a new
 * object is allocated. If the new object belongs to a TK pool, 
 * the physical page of this new object is flagged with the "typed"
 * flag.
 */
void llva_reg_obj(void* obj, void* MP, unsigned typed, void * eip) {
  void* pagetable = get_pagetable();
  
  pte_t* pte = get_pte((unsigned long)obj, pagetable);
  
  /*
   * Ensure that physical pages exist for the object.
   */
  if (!(pte_present(*pte))) {
    poolcheckfail ("MMU: Kernel object has no page frame: ", eip);
  }

  unsigned long pa = pte_val(*pte) >> PAGE_SHIFT;
  
  if (page_desc[pa].user) {
    poolcheckfail("MMU: A kernel object is allocated in a User page: %x.", __builtin_return_address(0));
  }

  if (page_desc[pa].sva) {
    poolcheckfail("MMU: A kernel object is allocated in a SVA page: %x.", __builtin_return_address(0));
  }  

  if (page_desc[pa].io) {
    poolcheckfail("MMU: A kernel object is allocated in an I/O page: %x.", __builtin_return_address(0));
  }  

  if (typed) {
    if (page_desc[pa].count) {
      poolcheckfail("MMU: TK object uses a TU virtual address: ", 
                    (pa * 4096), eip);
      poolcheckfail("MMU: TK object uses a TU virtual address: ", 
                    page_desc[pa].count, eip);
    } else {
      page_desc[pa].typed = 1;
    }
  } else {
#if 0
    if (page_desc[pa].untyped == 0) {
      printk("OK, I've just allocated a new untyped object in %d (%p)\n", pa, __builtin_return_address(0));
    }
#endif
    page_desc[pa].untyped = 1;
  }
}

/*
 * Called by the safecode allocator, mostly for the splay trees. The function
 * flags the physical page as used by the SVA engine.
 */
void llva_reg_sva_page(void* addr) {
  void* pagetable = get_pagetable();
  
  pte_t* pte = get_pte((unsigned long)addr, pagetable);
  
  unsigned long pa = pte_val(*pte) >> PAGE_SHIFT;
  
  if (page_desc[pa].count || page_desc[pa].typed) {
    poolcheckfail("MMU: Registering an already used sva page: %x!", __builtin_return_address(0));
  }
  
  page_desc[pa].sva = 1; 
}

void *
llva_virt_to_phys (void * virtual) {
  void* pagetable = get_pagetable();
  pte_t* pte = get_pte((unsigned long)virtual, pagetable);
  return (pte_val(*pte) & PAGE_MASK);
}

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

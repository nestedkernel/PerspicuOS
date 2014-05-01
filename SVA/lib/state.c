/*===- state.c - SVA Execution Engine  ------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * Provide intrinsics for manipulating the LLVA machine state.
 *
 *===----------------------------------------------------------------------===
 */

#if 1
#include <sva/config.h>
#endif
#include <sva/cfi.h>
#include <sva/callbacks.h>
#include <sva/util.h>
#include <sva/stack.h>
#include <sva/state.h>
#include <sva/interrupt.h>
#include <sva/mmu.h>
#include "sva/mmu_intrinsics.h"
#include <sva/x86.h>

/*****************************************************************************
 * Internal Utility Functions
 ****************************************************************************/

/*
 * Function: load_fp()
 *
 * Description:
 *  This function loads floating point state back on to the processor.
 */
static inline void
load_fp (sva_fp_state_t * buffer) {
  const unsigned int ts = 0x00000008;
  unsigned int cr0;
 
  /*
   * Save the state of the floating point unit.
   */
  if (buffer->present)
    __asm__ __volatile__ ("fxrstor %0" : "=m" (buffer->words));
  return;
}

/*
 * Function: save_fp()
 *
 * Description:
 *  Save the processor's current floating point state into the specified
 *  buffer.
 *
 * Inputs:
 *  buffer - A pointer to the buffer in which to save the data.
 */
static inline void
save_fp (sva_fp_state_t * buffer) {
  __asm__ __volatile__ ("fxsave %0" : "=m" (buffer->words) :: "memory");
  buffer->present = 1;
}

/*****************************************************************************
 * Externally Visibile Utility Functions
 ****************************************************************************/

sva_fp_state_t *
saveICFPState (void) {
  /* Get the current SVA thread */
  struct SVAThread * thread = getCPUState()->currentThread;

  /* Find the buffer into which we want to save state. */
  sva_fp_state_t * fp = thread->ICFP + (thread->ICFPIndex++);

  /*
   * Save the FP state.
   */
  save_fp (fp);
  return fp;
}

void
loadICFPState (void) {
  /* Get the current SVA thread */
  struct SVAThread * thread = getCPUState()->currentThread;

  /* Find the buffer into which we want to save state. */
  sva_fp_state_t * fp = thread->ICFP + (--(thread->ICFPIndex));

  /*
   * Save the FP state.
   */
  load_fp (fp);
  return;
}

void
installNewPushTarget (void) {
  /* Get the current SVA thread */
  struct SVAThread * threadp = getCPUState()->currentThread;

  /* Get the current interrput context */
  sva_icontext_t * icp = getCPUState()->newCurrentIC;

  //
  // Make sure we have room for another target.
  //
  if (threadp->numPushTargets == maxPushTargets)
    return;

  //
  // Add the new target.
  //
  threadp->validPushTargets[(threadp->numPushTargets)++] = icp->rdi;
  return;
}

/*****************************************************************************
 * Intrinsics for User-Space Applications
 ****************************************************************************/

void
getThreadRID (void) {
  /* Get the current interrput context */
  sva_icontext_t * icp = getCPUState()->newCurrentIC;

  /* Set the rax register with the pointer to the secret key */
  icp->rax = getCPUState()->currentThread->rid;
  return;
}

/*****************************************************************************
 * Interrupt Context Intrinsics
 ****************************************************************************/

#if 0
/*
 * Intrinsic: sva_init_icontext()
 *
 * Description:
 *  Take a new kernel stack and duplicate a given interrupt context on to
 *  the new stack.  This is primarily used for new thread creation.
 */
sva_sp_t
sva_init_icontext (sva_icontext_t * icontext, void * stackp)
{
  /* Working memory pointer */
  unsigned char * p;

  /* Old interrupt flags */
  unsigned int eflags;

  /*
   * Disable interrupts.
   */
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));

  /*
   * Find a nice place on the stack.
   */
  p = (((unsigned char *)(stackp)) - sizeof (sva_icontext_t));

  /*
   * Verify that the memory has the proper access.
   */
  sva_check_memory_read  (icontext, sizeof (sva_icontext_t));
  sva_check_memory_write (p,        sizeof (sva_icontext_t));

  /*
   * Copy the interrupt context on to the new stack.
   */
  __builtin_memcpy (p, icontext, sizeof (sva_icontext_t));

  /*
   * Re-enable interrupts.
   */
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
  return ((sva_sp_t)p);
}

void
sva_clear_icontext (sva_icontext_t * icontext)
{
  /* Old interrupt flags */
  unsigned int eflags;

  /*
   * Disable interrupts.
   */
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));

  /*
   * Verify that the memory has the proper access.
   */
  sva_check_memory_read  (icontext, sizeof (sva_icontext_t));

  /*
   * Clear all of the general purpose registers.
   */
  icontext->eax = 0;
  icontext->ebx = 0;
  icontext->ecx = 0;
  icontext->edx = 0;
  icontext->esi = 0;
  icontext->edi = 0;
  icontext->ebp = 0;

  /*
   * Initialize the interrupt state.
   */
  icontext->enable_shim = 0;
#if LLVA_SCLIMIT
  icontext->sc_disabled = 0;
#endif

  /*
   * Re-enable interrupts.
   */
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
  return;
}
#endif

/*
 * Intrinsic: sva_icontext_getpc()
 *
 * Description:
 *  Get the native code program counter value out of the interrupt context.
 */
uintptr_t
sva_icontext_getpc (void) {
  struct CPUState * cpuState = getCPUState();
  return cpuState->newCurrentIC->rip;
}

/*****************************************************************************
 * Miscellaneous State Manipulation Functions
 ****************************************************************************/

#if 0
/*
 * Intrinsic: sva_ipop_function0 ()
 *
 * Description:
 *  This intrinsic modifies the user space process code so that the
 *  function currently being executed is removed, with it's preceding function
 *  being executed instead.
 *
 * Inputs:
 *  exceptp  - A pointer to the exception handler saved state.
 *
 * TODO:
 *  o This intrinsic could conceivably cause a memory fault (either by
 *    accessing a stack page that isn't paged in, or by overwriting the stack).
 *    This should be addressed at some point.
 *
 *  o This intrinsic is assuming that I don't have anything on the stack.
 *    That's, um, not necessairly true all the time.
 */
void
sva_ipop_function0 (void * exceptp)
{
  /* User Context Pointer */
  sva_icontext_t * ep = exceptp;

  /* Old interrupt flags */
  unsigned int eflags;

  /*
   * Disable interrupts.
   */
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));

  do
  {
    /*
     * Check the memory.
     */
    sva_check_memory_write (ep, sizeof (sva_icontext_t));
    sva_check_memory_write (ep->rsp, sizeof (unsigned int));

    /*
     * Verify that this interrupt context has a stack pointer.
     */
    if (sva_is_privileged () && sva_was_privileged(ep))
    {
      __asm__ __volatile__ ("int %0\n" :: "i" (sva_state_exception));
      continue;
    }
    break;
  } while (1);

  /*
   * Pop the return PC pointer from the stack.
   */
  ep->rip = *((ep->rsp)++);

  /*
   * Re-enable interrupts.
   */
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
  return;
}
#endif

/*
 * Intrinsic: sva_ipush_function5 ()
 *
 * Description:
 *  This intrinsic modifies the most recent interrupt context so that the
 *  specified function is called with the given arguments when the state is
 *  reloaded on to the processor.
 *
 * Inputs:
 *  newf         - The function to call.
 *  p[1|2|3|4|5] - The parameters to pass to the function.
 *
 * TODO:
 *  o This intrinsic should check whether newf is a valid function for the
 *    appropriate mode (user or kernel).
 *
 *  o This intrinsic could conceivably cause a memory fault (either by
 *    accessing a stack page that isn't paged in, or by overwriting the stack).
 *    This should be addressed at some point.
 */
SECURE_WRAPPER(void,
sva_ipush_function5, void (*newf)(uintptr_t, uintptr_t, uintptr_t),
                     uintptr_t p1,
                     uintptr_t p2,
                     uintptr_t p3,
                     uintptr_t p4,
                     uintptr_t p5) {

  /*
   * Get the most recent interrupt context.
   */
  struct SVAThread * threadp = getCPUState()->currentThread;
  sva_icontext_t * ep = getCPUState()->newCurrentIC;

  /*
   * Verify that the target function is in the list of valid function targets.
   * Note that if no push targets have been specified, then any target is valid.
   */
  if (threadp->numPushTargets) {
    unsigned index = 0;
    unsigned char found = 0;
    for (index = 0; index < threadp->numPushTargets; ++index) {
      if (threadp->validPushTargets[index] == newf) {
        found = 1;
        break;
      }
    }

    if (!found) {
      panic ("SVA: Pushing bad value %lx\n", newf);
      return;
    }

    found = 0;
    for (index = 0; index < threadp->numPushTargets; ++index) {
      if (threadp->validPushTargets[index] == p5) {
        found = 1;
        break;
      }
    }

    if (!found) {
      panic ("SVA: Pushing bad sighandler value %lx\n", p5);
      return;
    }

  }

  /*
   * Check the memory.
   */
  sva_check_memory_write (ep, sizeof (sva_icontext_t));
  sva_check_memory_write (ep->rsp, sizeof (uintptr_t));

  /*
   * Place the arguments into the proper registers.
   */
  ep->rdi = p1;
  ep->rsi = p2;
  ep->rdx = p3;
  ep->rcx = p4;
  ep->r8  = p5;

  /*
   * Push a return program counter value on to the stack.  It should cause a
   * fault if the function returns.
   */
  *(--(ep->rsp)) = 0x0fec;

  /*
   * Set the return function to be the specificed function.
   */
  ep->rip = (uintptr_t) newf;

  /*
   * Mark the interrupt context as valid; if an sva_ialloca previously
   * invalidated it, an sva_ipush_function() makes it valid again.
   */
  ep->valid = 1;

  return;
}

/*
 * Intrinsic: sva_ipush_function0 ()
 *
 * Description:
 *  This intrinsic modifies the user space process code so that the
 *  specified function was called with the given arguments.
 *
 * Inputs:
 *  newf     - The function to call.
 *
 * NOTES:
 *  o This intrinsic could conceivably cause a memory fault (either by
 *    accessing a stack page that isn't paged in, or by overwriting the stack).
 *    This should be addressed at some point.
 */
void
sva_ipush_function0 (void (*newf)(void)) {
  sva_ipush_function5 (newf, 0, 0, 0, 0, 0);
  return;
}

/*
 * Intrinsic: sva_ipush_function1 ()
 *
 * Description:
 *  This intrinsic modifies the user space process code so that the
 *  specified function was called with the given arguments.
 *
 * Inputs:
 *  newf     - The function to call.
 *  param    - The parameter to send to the function.
 *
 * TODO:
 *  This currently only takes a function that takes a single integer
 *  argument.  Eventually, this should take any function.
 *
 * NOTES:
 *  o This intrinsic could conceivably cause a memory fault (either by
 *    accessing a stack page that isn't paged in, or by overwriting the stack).
 *    This should be addressed at some point.
 */
void
sva_ipush_function1 (void (*newf)(int), uintptr_t param) {
  sva_ipush_function5 (newf, param, 0, 0, 0, 0);
  return;
}

/*****************************************************************************
 * Integer State
 ****************************************************************************/

#if 0
/*
 * Intrinsic: sva_push_syscall ()
 *
 * Description:
 *  Modify the given LLVA state so that it appears that the specified system
 *  call has been invoked.
 */
void
sva_push_syscall (unsigned int sysnum, void * integerp, void * func)
{
  /* User Context Pointer */
  sva_integer_state_t * ep = integerp;

  /* Old interrupt flags */
  unsigned int eflags;

  /*
   * Disable interrupts.
   */
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));

#ifdef SC_INTRINCHECKS
  extern MetaPoolTy IntegerStatePool;
  struct node {
    void* left;
    void* right;
    char* key;
    char* end;
    void* tag;
  };
  struct node * np;
  unsigned long start;

  /*
   * Verify that the memory was part of a previous integer state.
   */
  np = getBounds (&IntegerStatePool, integerp);
  start = np->key;
  pchk_drop_obj (&IntegerStatePool, integerp);
  if (start != integerp)
    poolcheckfail ("Integer Check Failure", (unsigned)integerp, (void*)__builtin_return_address(0));
#endif

  /*
   * Check the memory.
   */
  sva_check_memory_write (ep,          sizeof (sva_integer_state_t));
  sva_check_memory_write (ep->rsp - 8, sizeof (unsigned int) * 8);

  /* Performance counters */
#if LLVA_COUNTERS
  ++sva_counters.sva_push_syscall;
  if (sva_debug) ++sva_local_counters.sva_push_syscall;
  sc_intrinsics[current_sysnum] |= MASK_LLVA_PUSH_SYSCALL;
#endif

  /*
   * Adjust the stack to hold the six parameters and a context pointer.
   */
  *(--(ep->rsp)) = (ep->rsp) + 1;
  *(--(ep->rsp)) = 0x00000006;
  *(--(ep->rsp)) = 0x00000005;
  *(--(ep->rsp)) = 0x00000004;
  *(--(ep->rsp)) = 0x00000003;
  *(--(ep->rsp)) = 0x00000002;
  *(--(ep->rsp)) = 0x00000001;

  /*
   * Push the return PC pointer on to the stack.
   */
  *(--(ep->rsp)) = sc_ret;

  /*
   * Set the return function to be the specified function.
   */
  ep->rip = (unsigned int) (func);

  /*
   * Disable restrictions on system calls since we don't know where this
   * function pointer came from.
   */
#if LLVA_SCLIMIT
  ep->sc_disabled = 0;
#endif

  /*
   * Re-enable interrupts.
   */
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
  return;
}

/*
 * Intrinsic: sva_get_integer_stackp ()
 *
 * Description:
 *  Return the stack pointer that is saved within the current integer state.
 */
unsigned char *
sva_get_integer_stackp (void * except_state)
{
#ifdef SC_INTRINCHECKS
  extern MetaPoolTy IntegerStatePool;
  struct node {
    void* left;
    void* right;
    char* key;
    char* end;
    void* tag;
  };
  struct node * np;
  unsigned long start;

  /*
   * Verify that the memory was part of a previous integer state.
   */
  np = getBounds (&IntegerStatePool, except_state);
  start = np->key;
  pchk_drop_obj (&IntegerStatePool, except_state);
  if (start != except_state)
    poolcheckfail ("Integer Check Failure", (unsigned)except_state, (void*)__builtin_return_address(0));
#endif

  return (((sva_integer_state_t *)except_state)->rsp);
}

/*
 * Intrinsic: sva_set_integer_stackp ()
 *
 * Description:
 *  Take the specified pointer and make it the stack pointer used in the
 *  specified integer state.
 */
void
sva_set_integer_stackp (sva_integer_state_t * intp, sva_sp_t p)
{
#ifdef SC_INTRINCHECKS
  extern MetaPoolTy IntegerStatePool;
  struct node {
    void* left;
    void* right;
    char* key;
    char* end;
    void* tag;
  };
  struct node * np;
  unsigned long start;

  /*
   * Verify that the memory was part of a previous integer state.
   */
  np = getBounds (&IntegerStatePool, intp);
  start = np->key;
  pchk_drop_obj (&IntegerStatePool, intp);
  if (start != intp)
    poolcheckfail ("Integer Check Failure", (unsigned)intp, (void*)__builtin_return_address(0));
#endif

  intp->rsp = (void *) (p);
  return;
}
#endif

/*
 * Function: checkIntegerForLoad ()
 *
 * Description:
 *  Perform all necessary checks on an integer state to make sure that it can
 *  be loaded on to the processor.
 *
 * Inputs:
 *  p - A pointer to the integer state to load.
 *
 * TODO:
 *  The checking code must also verify that there is enough stack space before
 *  proceeding.  Otherwise, state could get really messy.
 */
static inline void
checkIntegerForLoad (sva_integer_state_t * p) {
  /* Current code segment */
  unsigned int cs;

  /* Data segment to use for this privilege level */
  unsigned int ds = 0x18;

  /* Flags whether the input has been validated */
  unsigned int validated = 0;

  /* System call disable mask */
  extern unsigned int sva_sys_disabled;

#if 0
  /* Disable interrupts */
  __asm__ __volatile__ ("cli");
#endif

#if 0
  do
  {
#ifdef SC_INTRINCHECKS
    extern MetaPoolTy IntegerStatePool;
    struct node {
      void* left;
      void* right;
      char* key;
      char* end;
      void* tag;
    };
    struct node * np;
    unsigned long start;

    /*
     * Verify that the memory was part of a previous integer state.
     */
    np = getBounds (&IntegerStatePool, buffer);
    start = np->key;
    pchk_drop_obj (&IntegerStatePool, buffer);
    if (start != buffer)
      poolcheckfail ("Integer Check Failure", (unsigned)buffer, (void*)__builtin_return_address(0));
#endif

    /*
     * Verify that we won't fault if we read from the buffer.
     */
    sva_check_memory_read (buffer, sizeof (sva_integer_state_t));

    /*
     * Verify that we can access the stack pointed to inside the buffer.
     */
    sva_check_memory_write ((p->rsp) - 2, 8);

    /*
     * Grab the current code segment.
     */
    __asm__ __volatile__ ("movl %%cs, %0\n" : "=r" (cs));
    cs &= 0xffff;

    /*
     * If we're not operating at the same privilege level as when this state
     * buffer was saved, then generate an exception.
     */
    if (cs != (p->cs)) {
      __asm__ __volatile__ ("int %0\n" :: "i" (sva_state_exception));
      continue;
    }

#if 0
    /*
     * Configure the data segment to match the code segment, in case it somehow
     * became corrupted.
     */
    ds = ((cs == 0x10) ? (0x18) : (0x2B));
#endif

    /*
     * Validation is finished.  Continue.
     */
    validated = 1;
  } while (!validated);
#endif
  return;
}

/*
 * Function: flushSecureMemory()
 *
 * Description:
 *  This function flushes TLB entries and caches for a thread's secure memory.
 */
static inline void
flushSecureMemory (struct SVAThread * threadp) {
  /*
   * Invalidate all TLBs (including those with the global flag).  We do this
   * by first turning on and then turning off the PCID extension.  According
   * to the Intel Software Architecture Reference Manual, Volume 3,
   * Section 4.10.4, this will do the invalidation that we want.
   *
   * Experiments show that invalidating all of the TLBs is faster than
   * invalidating every page individually.  Since we usually flush on a context
   * switch, we just flushed all the TLBs anyway by changing CR3.  Therefore,
   * we lose speed by not flushing everything again.
   */
  __asm__ __volatile__ ("movq %cr4, %rax\n"
                        "movq %cr4, %rcx\n"
                        "orq $0x20000, %rax\n"
                        "andq $0xfffffffffffdffff, %rcx\n"
                        "movq %rax, %cr4\n"
                        "movq %rcx, %cr4\n");
  return;
}

#if 1
/*
 * Intrinsic: sva_swap_integer()
 *
 * Description:
 *  This intrinsic saves the current integer state and swaps in a new one.
 *
 * Inputs:
 *  newint - The new integer state to load on to the processor.
 *  statep - A pointer to a memory location in which to store the ID of the
 *           state that this invocation of sva_swap_integer() will save.
 *
 * Return value:
 *  0 - State swapping failed.
 *  1 - State swapping succeeded.
 */
/*TODO:!PERSP*/
uintptr_t
sva_swap_integer (uintptr_t newint, uintptr_t * statep) {
  panic("sva_swap_integer called!");
  /* Function for saving state */
  extern unsigned int save_integer (sva_integer_state_t * buffer);
  extern void load_integer (sva_integer_state_t * p);

  /* Old interrupt flags */
  uintptr_t rflags = sva_enter_critical();

  /* Pointer to the current CPU State */
  struct CPUState * cpup = getCPUState();

  /*
   * Get a pointer to the memory buffer into which the integer state should be
   * stored.  There is one such buffer for every SVA thread.
   */
  struct SVAThread * oldThread = cpup->currentThread;
  sva_integer_state_t * old = &(oldThread->integerState);

  /* Get a pointer to the saved state (the ID is the pointer) */
  struct SVAThread * newThread = (struct SVAThread *)(newint);
  sva_integer_state_t * new =  newThread ? &(newThread->integerState) : 0;

  /* Variables for registers for debugging */
  uintptr_t rsp, rbp;

  /*
   * If there is no place for new state, flag an error.
   */
  if (!newThread) panic ("SVA: No New Thread!\n");

  /*
   * Determine whether the integer state is valid.
   */
#if SVA_CHECK_INTEGER
  if ((pchk_check_int (new)) == 0) {
    poolcheckfail ("sva_swap_integer: Bad integer state", (unsigned)old, (void*)__builtin_return_address(0));
    /*
     * Re-enable interrupts.
     */
    sva_exit_critical (rflags);
    return 0;
  }
#endif

  /*
   * Save the value of the current kernel stack pointer, IST3, currentIC, and
   * the pointer to the global invoke frame pointer.
   */
  old->kstackp   = cpup->tssp->rsp0;
  old->ist3      = cpup->tssp->ist3;
  old->currentIC = cpup->newCurrentIC;
  old->ifp       = cpup->gip;

  /*
   * Save the floating point state.
   */
  save_fp (&(old->fpstate));

  /*
   * Save the current integer state.  Note that returning from sva_integer()
   * with a non-zero value means that we've just woken up from a context
   * switch.
   */
  if (save_integer (old)) {
    /*
     * We've awakened.
     */
#if SVA_CHECK_INTEGER
    /*
     * Mark the integer state invalid and return to the caller.
     */
    pchk_drop_int (old);

    /*
     * Determine what stack we're running on now.
     */
    pchk_update_stack ();
#endif

    /*
     * Re-enable interrupts.
     */
    sva_exit_critical (rflags);
    return 1;
  }

  /*
   * Save this functions return address because it can be overwritten by
   * calling interim FreeBSD code that does a native FreeBSD context switch.
   */
  old->hackRIP = __builtin_return_address(0);

  /*
   * If the current state is using secure memory, we need to flush out the TLBs
   * and caches that might contain it.
   */
  if (vg && (oldThread->secmemSize)) {
    /*
     * Save the CR3 register.  We'll need it later for sva_release_stack().
     */
    uintptr_t cr3;
    __asm__ __volatile__ ("movq %%cr3, %0\n" : "=r" (cr3));
    old->cr3 = cr3;

    /*
     * Get a pointer into the page tables for the secure memory region.
     */
    pml4e_t * secmemp = getVirtual (get_pagetable() + secmemOffset);

    /*
     * Mark the secure memory is unmapped in the page tables.
     */
    unprotect_paging ();
    *secmemp &= ~(PTE_PRESENT);
    protect_paging ();

    /*
     * Flush the secure memory page mappings.
     */
    flushSecureMemory (oldThread);
  }

  /*
   * Mark the saved integer state as valid.
   */
  old->valid = 1;

  /*
   * Inform the caller of the location of the last state saved.
   */
  *statep = (uintptr_t) oldThread;

  /*
   * Switch the CPU over to using the new set of interrupt contexts.  However,
   * don't change the stack pointer.
   */
  cpup->currentThread = newThread;

  /*
   * Now, reload the integer state pointed to by new.
   */
  if (new->valid) {
    /*
     * Verify that we can load the new integer state.
     */
    checkIntegerForLoad (new);

    /*
     * Switch the CPU over to using the new set of interrupt contexts.
     */
    cpup->currentThread = newThread;
    cpup->tssp->rsp0    = new->kstackp;
    cpup->tssp->ist3    = new->ist3;
    cpup->newCurrentIC  = new->currentIC;
    cpup->gip           = new->ifp;

    /*
     * If the new state uses secure memory, we need to map it into the page
     * table.  Note that we refetch the state information from the CPUState
     * to ensure that we're not accessing stale local variables.
     */
    if (vg && (newThread->secmemSize)) {
      /*
       * Get a pointer into the page tables for the secure memory region.
       */
      pml4e_t * secmemp = getVirtual (get_pagetable() + secmemOffset);

      /*
       * Restore the PML4E entry for the secure memory region.
       */
      uintptr_t mask = PTE_PRESENT | PTE_CANWRITE | PTE_CANUSER;
      if ((newThread->secmemPML4e & mask) != mask)
        panic ("SVA: Not Present: %lx %lx\n", newThread->secmemPML4e, mask);
      unprotect_paging ();
      *secmemp = newThread->secmemPML4e;
      protect_paging ();
    }

    /*
     * Invalidate the state that we're about to load.
     */
    new->valid = 0;

    /*
     * Load the floating point state.
     */
    load_fp (&(new->fpstate));

    /*
     * Load the rest of the integer state.
     */
    load_integer (new);
  }

  /*
   * The context switch failed.
   */
  sva_exit_critical (rflags);
  return 0; 
}
#endif

#if 0
unsigned char
sva_is_privileged  (void)

  unsigned int cs;
  __asm__ __volatile__ ("movl %%cs, %0\n" : "=r" (cs));
  return ((cs & 0x10) == 0x10);
}
#endif

/*
 * Intrinsic: sva_ialloca()
 *
 * Description:
 *  Allocate an object of the specified size on the current stack belonging to
 *  the most recent Interrupt Context and copy data into it.
 *
 * Inputs:
 *  size      - The number of bytes to allocate on the stack pointed to by the
 *              Interrupt Context.
 *  alignment - The power of two alignment to use for the memory object.
 *  initp     - A pointer to the data with which to initialize the memory
 *              object.  This is allowed to be NULL.
 *
 * NOTES:
 *  There is an issue with having sva_ialloca() copy data into the stack
 *  object.  The kernel uses copyout() to ensure that the memory is not part
 *  of kernel memory and can return EFAULT if the copy fails.  The question
 *  is how to make sva_ialloca() do the same thing.
 */
SECURE_WRAPPER(void *,
sva_ialloca, uintptr_t size, uintptr_t alignment, void * initp) {
  /* Pointer to allocated memory */
  void * allocap = 0;

  /* Determine if an allocation is permitted */
  unsigned char allocaOkay = 1;

  /*
   * Get the most recent interrupt context and the current CPUState and
   * thread.
   */
  struct CPUState * cpup = getCPUState();
  sva_icontext_t * icontextp = cpup->newCurrentIC;

  /*
   * If the Interrupt Context was privileged, then don't do an ialloca.
   */
  allocaOkay &= !(sva_was_privileged());

  /*
   * Determine whether initp points within the secure memory region.  If it
   * does, then don't allocate anything.
   */
  if (vg) {
    allocaOkay &= isNotWithinSecureMemory (initp);
  }

  /*
   * Check if the alignment is within range.
   */
  allocaOkay &= (alignment < 64);

  /*
   * Only perform the ialloca() if the Interrupt Context represents user-mode
   * state.
   */
  if (allocaOkay) {
    /*
     * Mark the interrupt context as invalid.  We don't want it to be placed
     * back on to the processor until an sva_ipush_function() pushes a new stack
     * frame on to the stack.
     */
    icontextp->valid = 0;

    /*
     * Perform the alloca.
     */
    allocap = icontextp->rsp;
    allocap -= size;

    /*
     * Align the pointer.
     */
    const uintptr_t mask = 0xffffffffffffffffu;
    allocap = (void *)((uintptr_t)(allocap) & (mask << alignment));

    /*
     * Verify that the stack pointer in the interrupt context is not within
     * kernel memory.
     */
    unsigned char spOkay = 1;
    if (isNotWithinSecureMemory(icontextp->rsp) &&
       ((allocap >= 0xffffffff00000000u) ||
        ((allocap + size) >= 0xffffffff00000000u))) {
      spOkay = 0;
    }

    /*
     * If the stack pointer is okay, go ahead and complete the operation.
     */
    if (spOkay) {
      /*
       * Fault in any necessary pages; the stack may be located in traditional
       * memory.
       */
      sva_check_memory_write (allocap, size);

      /*
       * Save the result back into the Interrupt Context.
       */
      icontextp->rsp = (unsigned long *) allocap;

      /*
       * Copy data in from the initializer.
       *
       * FIXME: This should use an invokememcpy() so that we know whether the
       *        address is valid.
       */
      if (initp)
        memcpy (allocap, initp, size);
    } else {
      allocap = 0;
    }
  }

  return allocap;
}

/*
 * Intrinsic: sva_load_icontext()
 *
 * Description:
 *  This intrinsic takes state saved by the Execution Engine during an
 *  interrupt and loads it into the latest interrupt context.
 */
SECURE_WRAPPER(void,
sva_load_icontext, void) {

  /*
   * Get the most recent interrupt context and the current CPUState and
   * thread.
   */
  struct CPUState * cpup = getCPUState();
  struct SVAThread * threadp = cpup->currentThread;
  sva_icontext_t * icontextp = cpup->newCurrentIC;

  /*
   * Verify that the interrupt context represents user-space state.
   */
  if (sva_was_privileged ()) {
      return;
  }

  /*
   * Verify that we have a free interrupt context to use.
   */
  if (threadp->savedICIndex < 1) {
      return;
  }

  /*
   * Load the interrupt context.
   */
  *icontextp = threadp->savedInterruptContexts[--(threadp->savedICIndex)];

  return;
}

/*
 * Intrinsic: sva_save_icontext()
 *
 * Description:
 *  Save the most recent interrupt context into SVA memory so that it can be
 *  restored later.
 *
 * Return value:
 *  0 - An error occured.
 *  1 - No error occured.
 */
SECURE_WRAPPER(unsigned char,
sva_save_icontext, void) {

  /*
   * Get the most recent interrupt context and the current CPUState and
   * thread.
   */
  struct CPUState * cpup = getCPUState();
  struct SVAThread * threadp = cpup->currentThread;
  sva_icontext_t * icontextp = cpup->newCurrentIC;

  /*
   * Verify that the interrupt context represents user-space state.
   */
  if (sva_was_privileged ()) {
      return 0;
  }

  /*
   * Verify that we have a free interrupt context to use.
   */
  if (threadp->savedICIndex > maxIC) {
      return 0;
  }

  /*
   * Save the interrupt context.
   */
  threadp->savedInterruptContexts[threadp->savedICIndex] = *icontextp;

  /*
   * Increment the saved interrupt context index and save it in a local
   * variable.
   */
  unsigned char savedICIndex = ++(threadp->savedICIndex);

  return savedICIndex;
}

#if 0
/*
 * Intrinsic: sva_load_stackp ()
 *
 * Description:
 *  Load on to the processor the stack pointer specified.
 */
void
sva_load_stackp  (sva_sp_t p)
{
  __asm__ __volatile__ ("movl %0, %%rsp\n" :: "r" (p));
  return;
}

/*
 * Intrinsic: sva_load_invoke()
 *
 * Description:
 *  Set the top of the invoke stack.
 */
void
sva_load_invoke (void * p)
{
  extern struct invoke_frame * gip;
  gip = p;
  return;
}

/*
 * Intrinsic: sva_save_invoke()
 *
 * Description:
 *  Save the current value of the top of the invoke stack.
 */
void *
sva_save_invoke (void)
{
  extern struct invoke_frame * gip;
  return gip;
}

unsigned int
sva_icontext_load_retvalue (void * icontext)
{
  return (((sva_icontext_t *)(icontext))->eax);
}

void
sva_icontext_save_retvalue (void * icontext, unsigned int value)
{
  (((sva_icontext_t *)(icontext))->eax) = value;
}

/*
 * Intrinsic: sva_get_icontext_stackp ()
 *
 * Description:
 *  Return the stack pointer that is saved within the specified interrupt
 *  context structure.
 */
unsigned char *
sva_get_icontext_stackp (void * icontext)
{
  /*
   * Verify that this interrupt context has a stack pointer.
   */
  while (sva_is_privileged () && sva_was_privileged(icontext))
  {
    __asm__ __volatile__ ("int %0\n" :: "i" (sva_state_exception));
  }

  return (((sva_icontext_t *)icontext)->rsp);
}

/*
 * Intrinsic: sva_set_icontext_stackp ()
 *
 * Description:
 *  Sets the stack pointer that is saved within the specified interrupt
 *  context structure.
 */
void
sva_set_icontext_stackp (void * icontext, void * stackp)
{
  /*
   * Verify that this interrupt context has a stack pointer.
   */
#if 0
  if (sva_is_privileged () && sva_was_privileged(icontext))
  {
    __asm__ __volatile__ ("int %0\n" :: "i" (sva_state_exception));
  }
#endif

  (((sva_icontext_t *)icontext)->rsp) = stackp;
  return;
}

/*
 * Intrinsic: sva_iset_privileged ()
 *
 * Description:
 *  Change the state of the interrupt context to have come from an unprivileged
 *  state.
 */
void
sva_iset_privileged (void * icontext, unsigned char privileged)
{
  /* Old interrupt flags */
  unsigned int eflags;

  /*
   * Disable interrupts.
   */
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));

  sva_icontext_t * p = icontext;
  if (privileged)
  {
    p->cs = 0x10;
    p->ds = 0x18;
    p->es = 0x18;
  }
  else
  {
    p->cs = 0x43;
    p->ds = 0x3B;
    p->es = 0x3B;
    p->ss = 0x3B;
  }

  /*
   * Re-enable interrupts.
   */
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
  return;
}

long long
sva_save_tsc (void)
{
  long long tsc;

  __asm__ __volatile__ ("rdtsc\n" : "=A" (tsc));
  return tsc;
}

void
sva_load_tsc (long long tsc)
{
  __asm__ __volatile__ ("wrmsr\n" :: "A" (tsc), "c" (0x10));
}
#endif

void
svaDummy (void) {
  panic ("SVA: svaDummy: Return to user space!\n");
  return;
}

/*
 * Intrinsic: sva_reinit_icontext()
 *
 * Description:
 *  Reinitialize an interrupt context so that, upon return, it begins to
 *  execute code at a new location.  This supports the exec() family of system
 *  calls.
 *
 * Inputs:
 *  transp - An identifier representing the entry point.
 *  priv   - A flag that, when set, indicates that the code will be executed in
 *           the processor's privileged mode.
 *  stack   - The value to set for the stack pointer.
 *  arg     - The argument to pass to the function entry point.
 */
SECURE_WRAPPER(void, 
sva_reinit_icontext, void * handle, unsigned char priv, uintptr_t stackp, uintptr_t arg) {
  /* Function entry point */
  void * func = handle;

  /*
   * Validate the translation handle.
   */
  struct translation * transp = (struct translation *)(handle);
  if (vg) {
    if ((translations <= transp) && (transp < translations + MAX_TRANSLATIONS)) {
      if (((uint64_t)transp - (uint64_t)translations) % sizeof (struct translation)) {
        panic ("SVA: Invalid translation handle: %p %p %lx\n", transp, translations, sizeof (struct translation));
        return;
      }
    } else {
      panic ("SVA: Out of range translation handle: %p %p %lx\n", transp, translations, sizeof (struct translation));
      return;
    }

    if (transp->used != 2)
      panic ("SVA: Bad transp: %d\n", transp->used);

    /* Grab the function to call from the translation handle */
    func = transp->entryPoint;
  }

  /*
   * Get the most recent interrupt context.
   */
  struct SVAThread * threadp = getCPUState()->currentThread;
  sva_icontext_t * ep = getCPUState()->newCurrentIC;

  /*
   * Check the memory.
   */
  sva_check_memory_write (ep, sizeof (sva_icontext_t));

  /*
   * Remove mappings to the secure memory for this thread.
   */
  if (vg && (threadp->secmemSize)) {
    /*
     * Get a pointer into the page tables for the secure memory region.
     */
    pml4e_t * secmemp = getVirtual (get_pagetable() + secmemOffset);

    /*
     * Mark the secure memory is unmapped in the page tables.
     */
    unprotect_paging ();
    *secmemp = 0;
    protect_paging ();

    /*
     * Delete the secure memory mappings from the SVA thread structure.
     */
    threadp->secmemSize = 0;
    threadp->secmemPML4e = 0;

    /*
     * Flush the secure memory page mappings.
     */
    flushSecureMemory (threadp);
  }

  /*
   * Clear out saved FP state.
   */
  threadp->ICFPIndex = 1;
  bzero (threadp->ICFP, sizeof (sva_fp_state_t));

  /*
   * Clear out any function call targets.
   */
  threadp->numPushTargets = 0;

  /*
   * Setup the call to the new function.
   */
  ep->rip = func;
  ep->rsp = stackp;
  ep->rdi = arg;

  /*
   * Setup the segment registers for the proper mode.
   */
  if (priv) {
    panic ("SVA: sva_reinit_context: No support for creating kernel state.\n");
  } else {
    ep->cs = 0x43;
    ep->ss = 0x3b;
    ep->ds = 0x3b;
    ep->es = 0x3b;
    ep->fs = 0x13;
    ep->gs = 0x1b;
    ep->rflags = (get_insecure_context_flags() & 0xfffu);
  }

  /*
   * Now that ghost memory has been reinitialized, install the key for this
   * bitcode file into the ghost memory and then invalidate the translation
   * handle since we've now used it.
   */
  if (vg) {
    memcpy (&(threadp->ghostKey), &(transp->key), sizeof (sva_key_t));
    transp->used = 0;
  }

  return;
}

/*
 * Intrinsic: sva_release_stack()
 *
 * Description:
 *  This intrinsic tells the virtual machine that the specified integer state
 *  should be discarded and that its stack is no longer a kernel stack.
 */
SECURE_WRAPPER(void,
sva_release_stack, uintptr_t id) {
  /* Get a pointer to the saved state (the ID is the pointer) */
  struct SVAThread * newThread = (struct SVAThread *)(id);
  sva_integer_state_t * new =  newThread ? &(newThread->integerState) : 0;

  /*
   * Ensure that we're not trying to release our own state.
   */
  if (newThread == getCPUState()->currentThread)
    return;

  /*
   * Release ghost memory.  Be sure to use the value of CR3 belonging to the
   * thread that is being released.
   */
  uintptr_t cr3 = ((((uintptr_t)new->cr3) & 0x000ffffffffff000u));
  for (uintptr_t size=0; size < newThread->secmemSize; size += X86_PAGE_SIZE) {
    if (vg) {
      unmapSecurePage ((unsigned char *)cr3, SECMEMSTART + size);
    }
  }

  /*
   * Mark the integer state as invalid.  This will prevent it from being
   * context switched on to the CPU.
   */
  new->valid = 0;

  /*
   * Mark the thread as available for reuse.
   */
  newThread->used = 0;
  return;
}

/*
 * Intrinsic: sva_init_stack()
 *
 * Description:
 *  Pointer to the integer state identifier used for context switching.
 *
 * Inputs:
 *  start_stackp - A pointer to the *beginning* of the kernel stack.
 *  length       - Length of the kernel stack in bytes.
 *  func         - The kernel function to execute when the new integer state
 *                 is swapped on to the processor.
 *  arg          - The first argument to the function.
 *
 * Return value:
 *  An identifier that can be passed to sva_swap_integer() to begin execution
 *  of the thread.
 */
SECURE_WRAPPER(uintptr_t,
sva_init_stack, unsigned char * start_stackp,
                uintptr_t length,
                void * func,
                uintptr_t arg1,
                uintptr_t arg2,
                uintptr_t arg3) {
  /* Working memory pointer */
  sva_icontext_t * icontextp;

  /* Working integer state */
  sva_integer_state_t * integerp;

  /* Function to use to return from system call */
  extern void sc_ret(void);

  /* Arguments allocated on the new stack */
  struct frame {
    /* Dummy return pointer ignored by load_integer() */
    void * dummy;

    /* Return pointer for the function frame */
    void * return_rip;
  } * args;

  /* End of stack */
  unsigned char * stackp = 0;

  /* Length of Stack */
  uintptr_t stacklen = length;

  /*
   * Find the last byte on the stack.
   */
  stackp = start_stackp + stacklen;

  /*
   * Verify that the stack is big enough.
   */
  if (stacklen < sizeof (struct frame)) {
    panic ("sva_init_stack: Invalid stacklen: %d!\n", stacklen);
  }

  /*
   * Verify that the function is a kernel function.
   */
  uintptr_t f = (uintptr_t)(func);
  if ((f <= SECMEMEND) || !CHECK_FUNC_LABEL(f)) {
    panic ("sva_init_stack: Invalid function %p\n", func);
  }

  /* Pointer to the current CPU State */
  struct CPUState * cpup = getCPUState();

  /*
   * Verify that no interrupts or traps have occurred (other than a system call
   * into the kernel).
   */
#if 0
  if (cpup->newCurrentIC < &(cpup->currentThread->interruptContexts[maxIC - 1]))
    panic ("Invalid IC!\n");
#endif

  /*
   * Get access to the old thread.
   */
  struct SVAThread * oldThread = cpup->currentThread;

  /*
   * Allocate a new SVA thread.
   */
  extern struct SVAThread * findNextFreeThread (void);
  struct SVAThread * newThread = findNextFreeThread();

  /*
   * Verify that the memory has the proper access.
   */
  sva_check_memory_read  (oldThread, sizeof (struct SVAThread));
  sva_check_memory_write (newThread, sizeof (struct SVAThread));

  /*
   * Copy over the secure memory mappings from the old thread to the new
   * thread.
   */
  if (vg) {
    newThread->secmemSize = oldThread->secmemSize;
    newThread->secmemPML4e = oldThread->secmemPML4e;
  }

  /*
   * Copy over the valid list of push targets for sva_ipush().
   */
  if (oldThread->numPushTargets) {
    unsigned index = 0;
    newThread->numPushTargets = oldThread->numPushTargets;
    for (index = 0; index < oldThread->numPushTargets; ++index) {
      newThread->validPushTargets[index] = oldThread->validPushTargets[index];
    }
  }

  /*
   * Copy over the last saved interrupted FP state.
   */
  if (oldThread->ICFPIndex) {
    *(newThread->ICFP) = *(oldThread->ICFP + oldThread->ICFPIndex - 1);
    newThread->ICFPIndex = 1;
  }

  /*
   * Allocate the call frame for the call to the system call.
   */
  stackp -= sizeof (struct frame);
  args = stackp;

  /*
   * Initialize the arguments to the system call.  Also setup the interrupt
   * context and return function pointer.
   */
  args->return_rip = sc_ret;

  /*
   * Initialze the integer state of the new thread of control.
   */
  integerp = &(newThread->integerState);
  integerp->rip = func;
  integerp->rdi = arg1;
  integerp->rsi = arg2;
  integerp->rdx = arg3;
  integerp->rsp = stackp;
  integerp->cs  = 0x43;
  integerp->ss  = 0x3b;
  integerp->valid = 1;
  integerp->rflags = 0x202;
#if 0
  integerp->ist3 = integerp->kstackp;
#endif
#if 1
  integerp->kstackp = stackp;
#endif
  integerp->fpstate.present = 0;

  /*
   * Initialize the interrupt context of the new thread.  Note that we use
   * the last IC.
   *
   * FIXME: The check on cpup->newCurrentIC is really a hack.  We should really
   *        fix the code to ensure that newCurrentIC is always set correctly
   *        and that the first interrupt context is at the end of the interrupt
   *        context list.
   */
  icontextp = integerp->currentIC = newThread->interruptContexts + maxIC - 1;
  *icontextp = *(cpup->newCurrentIC);

  /*
   * Set the return value to zero.
   *
   * FIXME: This is a hack.  Ideally, the return value setting code should do
   *        this.
   */
  icontextp->rax = 0;

  /* Mark the interrupt context as valid */
  icontextp->valid = 1;

  return (unsigned long) newThread;
}

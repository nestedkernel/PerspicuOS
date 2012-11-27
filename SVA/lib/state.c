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

#if 0
#include <sva/config.h>
#endif
#include <sva/callbacks.h>
#include <sva/util.h>
#include <sva/state.h>
#include <sva/interrupt.h>

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

/*
 * Intrinsic: sva_was_privileged()
 *
 * Description:
 *  This intrinsic flags whether the specified context was running in a
 *  privileged state before the interrupt/exception occurred.
 */
unsigned char
sva_was_privileged (sva_icontext_t * icontext)
{
  return (((icontext->cs) & 0x10) == 0x10);
}
#endif

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

/*
 * Intrinsic: sva_ipush_function0 ()
 *
 * Description:
 *  This intrinsic modifies the user space process code so that the
 *  specified function was called with the given arguments.
 *
 * Inputs:
 *  icontext - A pointer to the exception handler saved state.
 *  newf     - The function to call.
 *
 * NOTES:
 *  o This intrinsic could conceivably cause a memory fault (either by
 *    accessing a stack page that isn't paged in, or by overwriting the stack).
 *    This should be addressed at some point.
 */
void
sva_ipush_function0 (void * icontext, void (*newf)(void))
{
  /* User Context Pointer */
  sva_icontext_t * ip = icontext;

  /* Old interrupt flags */
  unsigned int eflags;

  /*
   * Disable interrupts.
   */
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));

  /*
   * Check the memory.
   */
  sva_check_memory_write (ip,      sizeof (sva_icontext_t));
  sva_check_memory_write (ip->rsp, sizeof (unsigned int) * 1);

  /*
   * Verify that this interrupt context has a stack pointer.
   */
#if 0
  if (sva_is_privileged () && sva_was_privileged(icontext))
  {
    __asm__ __volatile__ ("int %0\n" :: "i" (sva_state_exception));
  }
#endif

  /* Performance counters */
#if LLVA_COUNTERS
  ++sva_counters.sva_ipush_func;
  if (sva_debug) ++sva_local_counters.sva_ipush_func;
  sc_intrinsics[current_sysnum] |= MASK_LLVA_IPUSH_FUNCTION;
#endif

  /*
   * Push the return PC pointer on to the stack.
   */
  *(--(ip->rsp)) = ip->rip;

  /*
   * Set the return function to be the specificed function.
   */
  ip->rip = (unsigned int)newf;

  /*
   * Disable restrictions on system calls since we don't know where this
   * function pointer came from.
   */
#if LLVA_SCLIMIT
  ip->sc_disabled = 0;
#endif

  /*
   * Re-enable interrupts.
   */
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
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
 *  icontext - A pointer to the exception handler saved state.
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
sva_ipush_function1 (void * icontext, void (*newf)(int), int param)
{
  /* User Context Pointer */
  sva_icontext_t * ep = icontext;

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
    sva_check_memory_write (ep->rsp, sizeof (unsigned int) * 2);

    /*
     * Verify that this interrupt context has a stack pointer.
     */
    if (sva_is_privileged () && sva_was_privileged(icontext))
    {
      __asm__ __volatile__ ("int %0\n" :: "i" (sva_state_exception));
      continue;
    }
    break;
  } while (1);

  /* Performance counters */
#if LLVA_COUNTERS
  ++sva_counters.sva_ipush_func;
  if (sva_debug) ++sva_local_counters.sva_ipush_func;
  sc_intrinsics[current_sysnum] |= MASK_LLVA_IPUSH_FUNCTION;
#endif

  /*
   * Push the one argument on to the user space stack.
   */
  *(--(ep->rsp)) = param;

  /*
   * Push the return PC pointer on to the stack.
   */
  *(--(ep->rsp)) = ep->rip;

  /*
   * Set the return function to be the specificed function.
   */
  ep->rip = (unsigned int)newf;

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
#endif


/*
 * Intrinsic: sva_ipush_function4 ()
 *
 * Description:
 *  This intrinsic modifies the most recent interrupt context so that the
 *  specified function is called with the given arguments when the state is
 *  reloaded on to the processor.
 *
 * Inputs:
 *  newf     - The function to call.
 *  p[1|2|3] - The parameters to pass to the function.
 *
 * TODO:
 *  o This intrinsic should check whether newf is a valid function for the
 *    appropriate mode (user or kernel).
 *
 *  o This intrinsic could conceivably cause a memory fault (either by
 *    accessing a stack page that isn't paged in, or by overwriting the stack).
 *    This should be addressed at some point.
 */
void
sva_ipush_function4 (void (*newf)(uintptr_t, uintptr_t, uintptr_t),
                     uintptr_t p1,
                     uintptr_t p2,
                     uintptr_t p3,
                     uintptr_t p4) {
  /* Old interrupt flags */
  unsigned int rflags;

  /*
   * Disable interrupts.
   */
  rflags = sva_enter_critical();

  /*
   * Get the most recent interrupt context.
   */
  sva_icontext_t * ep = getCPUState()->newCurrentIC;

  /*
   * Check the memory.
   */
  sva_check_memory_write (ep, sizeof (sva_icontext_t));
  sva_check_memory_write (ep->rsp, sizeof (uintptr_t));

  /*
   * Place the arguments into the proper registers.
   */
  printf ("SVA: %lx %lx %lx %lx\n", p1, p2, p3, p4);
  ep->rdi = p1;
  ep->rsi = p2;
  ep->rdx = p3;
  ep->rcx = p4;

  /*
   * Push a return program counter value on to the stack.  It should cause a
   * fault if the function returns.
   */
  *(--(ep->rsp)) = 0x0000beefu;

  /*
   * Set the return function to be the specificed function.
   */
  ep->rip = (unsigned int)newf;

  /*
   * Re-enable interrupts.
   */
  sva_exit_critical (rflags);
  return;
}

/*****************************************************************************
 * Integer State
 ****************************************************************************/

#if 0
/*
 * Intrinsic: sva_push_function1 ()
 *
 * Description:
 *  This intrinsic modifies the saved integer state so that the specified
 *  function was called with the given arguments.
 *
 * Inputs:
 *  integer - A pointer to the exception handler saved state.
 *  newf    - The function to call.
 *  param   - The parameter to send to the function.
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
sva_push_function1 (void * integer, void (*newf)(int), int param)
{
  /* User Context Pointer */
  sva_integer_state_t * ep = integer;

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
  np = getBounds (&IntegerStatePool, integer);
  start = np->key;
  pchk_drop_obj (&IntegerStatePool, integer);
  if (start != integer)
    poolcheckfail ("Integer Check Failure", (unsigned)integer, (void*)__builtin_return_address(0));
#endif

  /*
   * Check the memory.
   */
  sva_check_memory_write (ep, sizeof (sva_integer_state_t));
  sva_check_memory_write (ep->rsp, sizeof (unsigned int) * 2);

  /* Performance counters */
#if LLVA_COUNTERS
  ++sva_counters.sva_push_func;
  if (sva_debug) ++sva_local_counters.sva_push_func;
  sc_intrinsics[current_sysnum] |= MASK_LLVA_PUSH_FUNCTION;
#endif

  /*
   * Push the one argument on to the user space stack.
   */
  *(--(ep->rsp)) = param;

  /*
   * Push the return PC pointer on to the stack.
   */
  *(--(ep->rsp)) = ep->rip;

  /*
   * Set the return function to be the specificed function.
   */
  ep->rip = (unsigned int)newf;

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

  /* Disable interrupts */
  __asm__ __volatile__ ("cli");

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
uintptr_t
sva_swap_integer (uintptr_t newint, uintptr_t * statep) {
  /* Function for saving state */
  extern unsigned int save_integer (sva_integer_state_t * buffer);
  extern void load_integer (sva_integer_state_t * p);

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

  /* Local CR3 register */
  uintptr_t cr3;

  /* Variables for registers for debugging */
  uintptr_t rsp, rbp;

  /*
   * Determine whether the integer state is valid.
   */
#if SVA_CHECK_INTEGER
  if ((pchk_check_int (new)) == 0) {
    poolcheckfail ("sva_swap_integer: Bad integer state", (unsigned)old, (void*)__builtin_return_address(0));
    return 0;
  }
#endif

  /*
   * Save the value of the current kernel stack pointer, IST3, and currentIC.
   */
  old->kstackp = cpup->tssp->rsp0;
  old->ist3 = cpup->tssp->ist3;
  old->currentIC = cpup->newCurrentIC;

  /*
   * Save the value of the CR3 register.
   */
  __asm__ __volatile__ ("movq %%cr3, %0\n"
                        "movq %0, %1\n"
                        : "=r" (cr3), "=m" (old->cr3));

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

#if 1
    /*
     * Fixup to where we will return.
     */
    uintptr_t * pcptr = __builtin_frame_address(0) + sizeof (void *);
    *pcptr = old->hackRIP;
#endif
    __asm__ __volatile__ ("movq %%rsp, %0\n"
                          "movq %%rbp, %1\n"
                          : "=m" (rsp), "=m" (rbp));
    printf ("SVA: Awake: %lx %lx: %lx\n", rsp, rbp, __builtin_return_address(0));
    return 1;
  }

  /*
   * Save this functions return address because it can be overwritten by
   * calling interim FreeBSD code that does a native FreeBSD context switch.
   */
  old->hackRIP = __builtin_return_address(0);

  /*
   * Mark the saved integer state as valid.
   */
  old->valid = 1;

  __asm__ __volatile__ ("movq %%rsp, %0\n"
                        "movq %%rbp, %1\n"
                        : "=m" (rsp), "=m" (rbp));
  printf ("SVA: Sleep: %lx %lx: %lx\n", rsp, rbp, __builtin_return_address(0));
#if 0
  printf ("SVA: saved: %p: rip = %lx, rsp = %lx, rbp = %lx\n", old, old->rip, old->rsp, old->rbp);
#endif

  /*
   * Inform the caller of the location of the last state saved.
   */
  *statep = (uintptr_t) oldThread;

  /*
   * If there is no place for new state, create a new SVA thread and start
   * using it without trying to load the new state.
   */
  if (!newThread) {
    /*
     * Create the new SVA Thread.
     */
    extern uintptr_t sva_mk_thread (void);
    newThread = (struct SVAThread *) sva_mk_thread ();

    /*
     * Switch the CPU over to using the new set of interrupt contexts.
     */
    cpup->currentThread = newThread;
#if 0
    cpup->tssp->ist3 = newThread->integerState.kstackp;
#endif

    return (uintptr_t) newThread;
  }

  /*
   * Switch the CPU over to using the new set of interrupt contexts.  However,
   * don't change the stack pointer.
   */
  cpup->currentThread = newThread;

#if 1
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
    cpup->tssp->rsp0 = new->kstackp;
    cpup->tssp->ist3 = new->ist3;
    cpup->newCurrentIC = new->currentIC;

    /*
     * Invalidate the state that we're about to load.
     */
    new->valid = 0;

    /*
     * Switch to the new address space.  We only modify CR3 if the two states
     * use different page tables because any changes to CR3 may flush the TLB.
     */
    if (old->cr3 != new->cr3) {
      cr3 = new->cr3;
      __asm__ __volatile__ ("movq %0, %%cr3\n" : : "r" (cr3));
    }

    /*
     * Load the rest of the integer state.
     */
    load_integer (new);
  }
#endif

  /*
   * The context switch failed.
   */
  return 0; 
}

#if 0
unsigned char
sva_is_privileged  (void)
{
  unsigned int cs;
  __asm__ __volatile__ ("movl %%cs, %0\n" : "=r" (cs));
  return ((cs & 0x10) == 0x10);
}

/*
 * Intrinsic: sva_ialloca()
 *
 * Description:
 *  Allocate space on the current stack frame for an object of the specified
 *  size.
 */
void *
sva_ialloca (void * icontext, unsigned int size)
{
  sva_icontext_t * p = icontext;

  /*
   * Verify that this interrupt context has a stack pointer.
   */
  while (sva_is_privileged () && sva_was_privileged(icontext))
  {
    __asm__ __volatile__ ("int %0\n" :: "i" (sva_state_exception));
  }

  /*
   * Perform the alloca.
   */
  return (p->rsp -= ((size / 4) + 1));
}

/*
 * Intrinsic: sva_load_icontext()
 *
 * Description:
 *  This intrinsic takes state saved by the Execution Engine during an
 *  interrupt and loads it into the specified interrupt context buffer.
 */
void
sva_load_icontext (sva_icontext_t * icontextp, sva_integer_state_t * statep)
{
  /* Old interrupt flags */
  unsigned int eflags;

  /*
   * Disable interrupts.
   */
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));

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
    np = getBounds (&IntegerStatePool, statep);
    start = np->key;
    pchk_drop_obj (&IntegerStatePool, statep);
    if (start != statep)
      poolcheckfail ("Integer Check Failure", (unsigned)statep, (void*)__builtin_return_address(0));
#endif

    sva_check_memory_read (statep, sizeof (sva_icontext_t));
    sva_check_memory_write (icontextp, sizeof (sva_icontext_t));

    /*
     * Verify that this interrupt context has a stack pointer.
     */
    if (sva_is_privileged () && sva_was_privileged(icontextp))
    {
      __asm__ __volatile__ ("int %0\n" :: "i" (sva_state_exception));
      continue;
    }
    break;
  } while (1);

  /*
   * Currently, the interrupt context and integer state are one to one
   * identical.  This means that they can just be copied over.
   */
  __builtin_memcpy (icontextp, statep, sizeof (sva_icontext_t));

  /*
   * Re-enable interrupts.
   */
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
  return;
}

/*
 * Intrinsic: sva_save_icontext()
 *
 * Description:
 *  This intrinsic takes state saved by the Execution Engine during an
 *  interrupt and saves it as an integer state structure.
 */
void
sva_save_icontext (sva_icontext_t * icontextp, sva_integer_state_t * statep)
{
  /* Old interrupt flags */
  unsigned int eflags;

  /*
   * Disable interrupts.
   */
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));

  do
  {

    sva_check_memory_read  (icontextp, sizeof (sva_icontext_t));
    sva_check_memory_write (statep,    sizeof (sva_icontext_t));

    /*
     * Verify that this interrupt context has a stack pointer.
     */
    if (sva_is_privileged () && sva_was_privileged(icontextp))
    {
      __asm__ __volatile__ ("int %0\n" :: "i" (sva_state_exception));
      continue;
    }
    break;
  } while (1);

  /*
   * Currently, the interrupt context and integer state are one to one
   * identical.  This means that they can just be copied over.
   */
  __builtin_memcpy (statep, icontextp, sizeof (sva_icontext_t));

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
   * Register the integer state with the Execution Engine's memory safety code.
   */
  pchk_reg_obj (&IntegerStatePool, statep, 72);
#endif

  /*
   * Re-enable interrupts.
   */
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
  return;
}

/*
 * Intrinsic: sva_load_fp()
 *
 * Description:
 *  This intrinsic loads floating point state back on to the processor.
 */
void
sva_load_fp (void * buffer)
{
  const int ts = 0x00000008;
  unsigned int cr0;
  sva_fp_state_t * p = buffer;
  extern unsigned char sva_fp_used;
 
  /* Old interrupt flags */
  unsigned int eflags;

  /*
   * Disable interrupts.
   */
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));

#if LLVA_COUNTERS
  ++sva_counters.sva_load_fp;
  if (sva_debug) ++sva_local_counters.sva_load_fp;
  sc_intrinsics[current_sysnum] |= MASK_LLVA_LOAD_FP;
#endif

  /*
   * Save the state of the floating point unit.
   */
  __asm__ __volatile__ ("frstor %0" : "=m" (p->state));

  /*
   * Mark the FPU has having been unused.  The first FP operation will cause
   * an exception into the Execution Engine.
   */
  __asm__ __volatile__ ("movl %%cr0, %0\n"
                        "orl  %1,    %0\n"
                        "movl %0,    %%cr0\n" : "=&r" (cr0) : "r" ((ts)));
  sva_fp_used = 0;

  /*
   * Re-enable interrupts.
   */
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
  return;
}

/*
 * Intrinsic: sva_save_fp()
 *
 * Description:
 *  Save the processor's current floating point state into the specified
 *  buffer.
 *
 * Inputs:
 *  buffer - A pointer to the buffer in which to save the data.
 *  always - Only save state if it was modified since the last load FP state.
 */
int
sva_save_fp (void * buffer, int always)
{
  sva_fp_state_t * p = buffer;
  extern unsigned char sva_fp_used;

  /* Old interrupt flags */
  unsigned int eflags;

  /*
   * Disable interrupts.
   */
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));

  if (always || sva_fp_used)
  {
#if LLVA_COUNTERS
    ++sva_counters.sva_save_fp;
    if (sva_debug) ++sva_local_counters.sva_save_fp;
    sc_intrinsics[current_sysnum] |= MASK_LLVA_SAVE_FP;
#endif
    __asm__ __volatile__ ("fnsave %0" : "=m" (p->state) :: "memory");

    /*
     * Re-enable interrupts.
     */
    if (eflags & 0x00000200)
      __asm__ __volatile__ ("sti":::"memory");
    return 1;
  }

  /*
   * Re-enable interrupts.
   */
  if (eflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
  return 0;
}

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
    p->cs = 0x23;
    p->ds = 0x2B;
    p->es = 0x2B;
    p->ss = 0x2B;
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
unsigned int
sva_init_stack (unsigned char * start_stackp,
                uintptr_t length,
                void * func,
                unsigned int arg) {
  /* Working memory pointer */
  sva_icontext_t * icontextp;

  /* Working integer state */
  sva_integer_state_t * integerp;

  /* Function to use to return from system call */
  extern void sc_ret(void);

  /* Arguments allocated on the new stack */
  struct frame {
    /* Return pointer for the function frame */
    void * return_rip;
  } * args;

  /* Old interrupt flags */
  uintptr_t rflags;

  /* End of stack */
  unsigned char * stackp = 0;

  /* Length of Stack */
  uintptr_t stacklen = stacklen;

  /*
   * Disable interrupts.
   */
  rflags = sva_enter_critical();

  /*
   * Find the last byte on the stack.
   */
  stackp = start_stackp + stacklen;

  /*
   * Verify that the stack is big enough.
   */
  if (stacklen < sizeof (struct frame)) {
    return 0;
  }

  /* Pointer to the current CPU State */
  struct CPUState * cpup = getCPUState();

  /*
   * Verify that no interrupts or traps have occurred (other than a system call
   * into the kernel).
   */
  if (cpup->newCurrentIC < &(cpup->currentThread->interruptContexts[maxIC - 1]))
    return 0;

  /*
   * Get access to the old thread.
   */
  struct SVAThread * oldThread = cpup->currentThread;

  /*
   * Allocate a new SVA thread.
   */
  extern uintptr_t sva_mk_thread (void);
  struct SVAThread * newThread = (struct SVAThread *) sva_mk_thread ();

  /*
   * Verify that the memory has the proper access.
   */
  sva_check_memory_read  (oldThread, sizeof (struct SVAThread));
  sva_check_memory_write (newThread, sizeof (struct SVAThread));

  /*
   * Copy the old SVA thread state into the new thread state.
   */
  *newThread = *oldThread;

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
  bzero (integerp, sizeof (sva_integer_state_t));
  integerp->rip = func;
  integerp->rdi = arg;
  integerp->rsp = stackp;
  integerp->cs  = 0x10;

  /*
   * Re-enable interrupts.
   */
  sva_exit_critical (rflags);
  return (unsigned int) integerp;
}

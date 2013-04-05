#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/pcpu.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <machine/vmparam.h>
#include <machine/pcb.h>

/*
 * Prototypes for the real functions.
 */
extern int real_copyin(const void * __restrict udaddr, void * __restrict kaddr, size_t len) __nonnull(1) __nonnull(2);

extern int real_copyout(const void * __restrict kaddr, void * __restrict udaddr, size_t len) __nonnull(1) __nonnull(2);

/*
 * Implementations of the functions that use the SVA-OS intrinsics.
 */
int
copyinstr(const void * __restrict udaddr, void * __restrict kaddr,
	        size_t len, size_t * __restrict lencopied) {
  /* Number of bytes copied */
  uintptr_t copySize;

  /*
   * Ensure that the copy won't read in kernel-space memory for the string.
   */
  if (VM_MAXUSER_ADDRESS <= udaddr)
    return EFAULT;

  if (len >= (VM_MAXUSER_ADDRESS - (uintptr_t)udaddr))
    len = (VM_MAXUSER_ADDRESS - (uintptr_t)udaddr);

  /*
   * Note that we want to use SVA to unwind the stack if we hit a fault.
   */
  PCPU_GET(curpcb)->pcb_onfault = 1;

  /*
   * Perform the copy.
   */
  copySize = sva_invokestrncpy (kaddr, udaddr, len);

  /*
   * Note that we aren't expecting a fault now.
   */
  PCPU_GET(curpcb)->pcb_onfault = 0;

  /*
   * Determine if the string name is too long or if we hit a fault.
   */
  if (copySize == -1)
    return EFAULT;

  if (copySize == len)
    return ENAMETOOLONG;

  /*
   * Report the number of bytes copied to the caller.
   */
  if (lencopied)
    *lencopied = copySize + 1;
  return 0;
}

int
copyin(const void * __restrict udaddr,
       void * __restrict kaddr,
	    size_t len) {
  uintptr_t retval;
  if (sva_invoke (udaddr, kaddr, len, &retval, real_copyin))
    return EFAULT;
  else
    return (int)(retval);
}

int
copyout(const void * __restrict kaddr,
        void * __restrict udaddr,
        size_t len) {
  uintptr_t retval;
  if (sva_invoke (kaddr, udaddr, len, &retval, real_copyout))
    return EFAULT;
  else
    return (int)(retval);
}


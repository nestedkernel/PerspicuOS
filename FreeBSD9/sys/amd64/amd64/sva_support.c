#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>

/*
 * Prototypes for the real functions.
 */
extern int real_copyin(const void * __restrict udaddr, void * __restrict kaddr, size_t len) __nonnull(1) __nonnull(2);

extern int real_copyout(const void * __restrict kaddr, void * __restrict udaddr, size_t len) __nonnull(1) __nonnull(2);

/*
 * Implementations of the functions that use the SVA-OS intrinsics.
 */
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


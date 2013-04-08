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

extern long	real_fuword(const void *base);
extern int	real_fubyte(const void *base);
extern int	real_fuword16(void *base);
extern int32_t	real_fuword32(const void *base);
extern int64_t	real_fuword64(const void *base);

extern int real_subyte(void *base, int byte);
extern int real_suword(void *base, long word);
extern int real_suword16(void *base, int word);
extern int real_suword32(void *base, int32_t word);
extern int real_suword64(void *base, int64_t word);

extern uint32_t real_casuword32(volatile uint32_t *base, uint32_t oldval, uint32_t newval);
extern u_long	 real_casuword(volatile u_long *p, u_long oldval, u_long newval);

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
  if (sva_invoke (udaddr, kaddr, len, &retval, real_copyin)) {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return EFAULT;
  } else {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return (int)(retval);
  }
}

int
copyout(const void * __restrict kaddr,
        void * __restrict udaddr,
        size_t len) {
  uintptr_t retval;
  if (sva_invoke (kaddr, udaddr, len, &retval, real_copyout)) {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return EFAULT;
  } else {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return (int)(retval);
  }
}

int64_t
fuword64 (const void * addr) {
  uintptr_t retval;
  if (sva_invoke (addr, 0, 0, &retval, real_fuword64)) {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return -1;
  } else {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return (int64_t)(retval);
  }
}

int64_t
fuword (const void * addr) {
  return fuword64 (addr);
}

int32_t
fuword32 (const void * addr) {
  uintptr_t retval;
  if (sva_invoke (addr, 0, 0, &retval, real_fuword32)) {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return -1;
  } else {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return (int32_t)(retval);
  }
}

int
fuword16 (void * addr) {
  uintptr_t retval;
  if (sva_invoke (addr, 0, 0, &retval, real_fuword16)) {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return -1;
  } else {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return (int)(retval);
  }
}

int
fubyte (const void * addr) {
  uintptr_t retval;
  if (sva_invoke (addr, 0, 0, &retval, real_fubyte)) {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return -1;
  } else {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return (int)(retval);
  }
}

int
subyte(void *base, int byte) {
  uintptr_t retval;
  if (sva_invoke (base, byte, 0, &retval, real_subyte)) {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return -1;
  } else {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return (int)(retval);
  }
}

int
suword(void *base, long word) {
  uintptr_t retval;
  if (sva_invoke (base, word, 0, &retval, real_suword)) {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return -1;
  } else {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return (int)(retval);
  }
}

int
suword16(void *base, int word) {
  uintptr_t retval;
  if (sva_invoke (base, word, 0, &retval, real_suword16)) {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return -1;
  } else {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return (int)(retval);
  }
}

int
suword32(void *base, int32_t word) {
  uintptr_t retval;
  if (sva_invoke (base, word, 0, &retval, real_suword32)) {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return -1;
  } else {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return (int)(retval);
  }
}

int
suword64(void *base, int64_t word) {
  uintptr_t retval;
  if (sva_invoke (base, word, 0, &retval, real_suword64)) {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return -1;
  } else {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return (int)(retval);
  }
}

uint32_t
casuword32 (volatile uint32_t *base, uint32_t oldval, uint32_t newval) {
  uintptr_t retval;
  if (sva_invoke (base, oldval, newval, &retval, real_casuword32)) {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return -1;
  } else {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return (int)(retval);
  }
}

u_long
casuword(volatile u_long *p, u_long oldval, u_long newval) {
  uintptr_t retval;
  if (sva_invoke (p, oldval, newval, &retval, real_casuword)) {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return -1;
  } else {
    PCPU_GET(curpcb)->pcb_onfault = 0;
    return (int)(retval);
  }
}

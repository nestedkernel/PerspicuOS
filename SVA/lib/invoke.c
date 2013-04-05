/*===- invoke.c - SVA Execution Engine  ----------------------------------===
 * 
 *                     The LLVM Compiler Infrastructure
 *
 * This file was developed by the LLVM research group and is distributed under
 * the GNU General Public License Version 2. See the file named COPYING for
 * details.  Note that the code is provided with no warranty.
 *
 * Copyright 2006-2009 University of Illinois.
 * Portions Copyright 1997 Andi Kleen <ak@muc.de>.
 * Portions Copyright 1997 Linus Torvalds.
 * 
 *===----------------------------------------------------------------------===
 *
 * The code from the Linux kernel was brought in and modified on 2006/05/09.
 * The code was primarily used for its fast strncpy() and strnlen()
 * implementations; the code for handling MMU faults during the memory
 * operations were modified for sva_invokestrncpy() and possibly modified for
 * sva_invokestrnlen().
 *
 *===----------------------------------------------------------------------===
 *
 * This is the code for the SVA Execution Engine that manages invoke/unwind
 * functionality.
 *
 *===----------------------------------------------------------------------===
 */

#include <sva/state.h>
#include <sva/util.h>

#include "offsets.h"

/*
 * Intrinsic: sva_unwind ()
 *
 * Description:
 *  Unwind the stack specifed by the interrupt context.
 */
void
sva_iunwind (void) {
  /* Current processor status flags */
  uintptr_t rflags;

  /* Assembly code that finishes the unwind */
  extern void sva_invoke_except(void);
  extern void sva_memcpy_except(void);

  /*
   * Disable interrupts.
   */
  rflags = sva_enter_critical();

  /*
   * Get the pointer to the most recent invoke frame and interrupt context.
   */
  struct CPUState * cpup    = getCPUState();
  struct invoke_frame * gip = cpup->gip;
  sva_icontext_t * ip       = cpup->newCurrentIC;

  /*
   * Do nothing if there is no invoke stack.
   */
  if (!gip) {
    /*
     * Re-enable interrupts.
     */
    sva_exit_critical (rflags);
    return;
  }

  /*
   * Check the invoke frame for read access.
   */
  sva_check_memory_read (gip, sizeof (struct invoke_frame));

  /*
   * Check the interrupt context pointer for write access.
   */
  sva_check_memory_write (ip, sizeof (sva_icontext_t));

  /*
   * Adjust the program state so that it resumes inside the invoke instruction.
   */
  switch (gip->cpinvoke) {
    case INVOKE_NORMAL:
      ip->rip = sva_invoke_except;
      break;

#if 0
    case INVOKE_MEMCPY_W:
      ip->rcx = (ip->rcx) << 2;
    case INVOKE_MEMCPY_B:
#endif
    case INVOKE_STRNCPY:
      ip->rip = (void *)(gip->rbx);
      break;

    default:
      panic ("SVA: Other Invoke Frames Unsupported!\n");
      break;
  }

  /*
   * Re-enable interrupts.
   */
  sva_exit_critical (rflags);
  return;
}

#if 0
unsigned int
sva_invokememcpy (void * to, const void * from, unsigned long count)
{
  /* The invoke frame placed on the stack */
  struct invoke_frame frame;

  /* The invoke frame pointer */
  extern struct invoke_frame * gip;

  /* Return value */
  unsigned int ret = 0;

  /* Mark the frame as being used for a memcpy */
  frame.cpinvoke = INVOKE_MEMCPY_W;
  frame.next = gip;

  /* Make it the top invoke frame */
  gip = &frame;

  /* Perform the memcpy */
  __asm__ __volatile__ ("nop\nnop");
  __asm__ __volatile__ (
                        ".global sva_memcpy_except\n"
                        ".type sva_memcpy_except, @function\n"
                        "movl $1f, %2\n"
                        "rep; movsl\n"
                        "movl $2, %0\n"
                        "movl %%edx, %%ecx\n"
                        "rep; movsb\n"
                        "1:\n"
                        "movl %%ecx, %1\n"
                        : "=m" (frame.cpinvoke), "=&a" (ret), "=m" (frame.esi)
                        : "D" (to),
                          "S" (from),
                          "c" (count / 4),
                          "d" (count & 0x3));

  /* Unlink the last invoke frame */
  gip = frame.next;
  return ret;
}
#endif

/*
 * Intrinsic: sva_invokestrncpy()
 *
 * Description:
 *  Copy a zero terminated string from one location to another.
 *
 * Inputs:
 *  dst   - The destination string.  It cannot overlap src.
 *  src   - The source string
 *  count - The maximum number of bytes to copy.
 *
 * Outputs:
 *  dst   - The destination string
 *
 * Return value:
 *  Return the number of bytes copied (not counting the string terminator),
 *  or -1 if a fault occurred.
 *
 * NOTE:
 *  This function contains inline assembly code from the original i386 Linux
 *  2.4.22 kernel code.  I believe it originates from the
 *  __do_strncpy_from_user() macro in arch/i386/lib/usercopy.c.
 *
 * TODO:
 *  It is not clear whether this version will be as fast as the x86_64 version
 *  in FreeBSD 9.0; this version is an x86_64 port of the original Linux 2.4.22
 *  code for 32-bit processors.
 */
uintptr_t
sva_invokestrncpy (char * dst, const char * src, uintptr_t count) {
  /* The invoke frame placed on the stack */
  struct invoke_frame frame;

  /* Return value */
  uintptr_t ret = 0;

  /* Other variables */
  uintptr_t res;
  uintptr_t __d0, __d1, __d2;

  /*
   * Determine if there is anything to copy.  If not, then return now.
   */
  if (count == 0)
    return 0;

  /*
   * Get the pointer to the most recent invoke frame.
   */
  struct CPUState * cpup    = getCPUState();
  struct invoke_frame * gip = cpup->gip;

  /* Mark the frame as being used for a memcpy */
  frame.cpinvoke = INVOKE_STRNCPY;
  frame.next = gip;

  /* Make it the top invoke frame */
  cpup->gip = &frame;

  /* Perform the strncpy */
  __asm__ __volatile__(
    " movq $2f, %5\n"
    "0: lodsb\n"
    " stosb\n"
    " testb %%al,%%al\n"
    " jz 1f\n"
    " decq %1\n"
    " jnz 0b\n"
    " jmp 1f\n"
    "2: movq $0xffffffffffffffff, %0\n"
    " jmp 3f\n"
    "1: subq %1,%0\n"
    "3:\n"
    : "=d"(res), "=c"(count), "=&a" (__d0), "=&S" (__d1),
      "=&D" (__d2), "=m" (frame.rbx)
    : "i"(0), "0"(count), "1"(count), "3"(src), "4"(dst)
    : "memory");

  /*
   * Pop off the invoke frame.
   */
  cpup->gip = frame.next;
  return res;
}

#if 0
/*
 * Return value:
 *  Returns the number of bytes left unset.
 */
unsigned int
sva_invokememset (void * s, char c, unsigned int count)
{
  /* The invoke frame placed on the stack */
  struct invoke_frame frame;

  /* The invoke frame pointer */
  extern struct invoke_frame * gip;

  /* Return value */
  unsigned int ret = 0;

  /* Other variables */
  int d0, d1;

  /* Mark the frame as being used for a memcpy */
  frame.cpinvoke = INVOKE_MEMSET;
  frame.next = gip;

  /* Make it the top invoke frame */
  gip = &frame;

  /* Perform the memset */
  __asm__ __volatile__(
    "movl $1f, %2\n"
    "rep\n"
    "stosb\n"
    "1:\n"
    : "=&c" (d0), "=&D" (d1), "=m" (frame.esi)
    : "a" (c),"1" (s),"0" (count)
    : "memory");
  return d0;
}


/*
 * NOTE:
 *  This function contains inline assembly code from the original i386 Linux
 *  kernel code.  I believe it originates from the strnlen_user() function in
 *  arch/i386/lib/usercopy.c.
 */
unsigned int
sva_invokestrnlen (void * s, unsigned long n, unsigned long mask)
{
  /* The invoke frame placed on the stack */
  struct invoke_frame frame;

  /* The invoke frame pointer */
  extern struct invoke_frame * gip;

  /* Return value */
  unsigned int ret = 0;

  /* Mark the frame as being used for a memcpy */
  frame.cpinvoke = INVOKE_MEMCPY_W;
  frame.next = gip;

  /* Make it the top invoke frame */
  gip = &frame;

  /* Perform the strnlen */
  unsigned long res, tmp;
  __asm__ __volatile__ ("nop\nnop");
  __asm__ __volatile__(
                       "	testl %0, %0\n"
                       "	jz 3f\n"
                       "	andl %0,%%ecx\n"
                       "0:	repne; scasb\n"
                       "	setne %%al\n"
                       "	subl %%ecx,%0\n"
                       "	addl %0,%%eax\n"
                       "1:\n"
                       ".section .fixup,\"ax\"\n"
                       "2:	xorl %%eax,%%eax\n"
                       "	jmp 1b\n"
                       "3:	movb $1,%%al\n"
                       "	jmp 1b\n"
                       ".previous\n"
                       ".section __ex_table,\"a\"\n"
                       "	.align 4\n"
                       "	.long 0b,2b\n"
                       ".previous"
                       :"=r" (n), "=D" (s), "=a" (res), "=c" (tmp)
                       :"0" (n), "1" (s), "2" (0), "3" (mask)
                       :"cc");

  /* Unlink the last invoke frame */
  gip = frame.next;
  return res;
}
#endif

/*===- debug.c - SVA Execution Engine  ------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * Debugging code for the Execution Engine when linked into the operating
 * system kernel.
 *
 *===----------------------------------------------------------------------===
 */

#include <sva/state.h>
#include <sva/interrupt.h>
#include <machine/frame.h>

/*****************************************************************************
 * Cheater's Code
 ****************************************************************************/

/*
 * Function: sva_trapframe()
 *
 * Description:
 *  Convert the state as represented by the Execution Engine back into FreeBSD's
 *  trapframe structure.
 *
 *  The reason for doing this is that it allows me to progressively move the
 *  kernel to using SVA for interrupts without completely breaking it.
 */
void
sva_trapframe (struct trapframe * tf) {
  /*
   * Fetch the interrupt context.
   */
  sva_icontext_t * p = get_CPUState()->currentIContext;

  /*
   * Store the fields into the trap frame.
   */
  tf->tf_rdi = p->rdi;
  tf->tf_rsi = p->rsi;
  tf->tf_rcx = p->rcx;
  tf->tf_r8  = p->r8;
  tf->tf_r9  = p->r9;
  tf->tf_rax = p->rax;
  tf->tf_rbx = p->rbx;
  tf->tf_rbp = p->rbp;
  tf->tf_r10 = p->r10;
  tf->tf_r11 = p->r11;
  tf->tf_r12 = p->r12;
  tf->tf_r13 = p->r13;
  tf->tf_r14 = p->r14;
  tf->tf_r15 = p->r15;

  tf->tf_trapno = p->trapno;


  tf->tf_fs = p->fs;
  tf->tf_gs = p->gs;
  tf->tf_addr = 0;
  tf->tf_es = p->es;
#if 0
  tf->tf_ds = p->ds;
#else
  tf->tf_ds = 0;
#endif

  tf->tf_err = p->code;
  tf->tf_rip = p->rip;
  tf->tf_cs = p->cs;
  tf->tf_rflags = p->rflags;
  tf->tf_rsp = (unsigned long)(p->rsp);
  tf->tf_ss = p->ss;

  return;
}

/*
 * Function: sva_icontext()
 *
 * Description:
 *  Convert the state as represented by the FreeBSD's trapframe structure back
 *  into the interrupt context.
 *
 *  The reason for doing this is that it allows me to progressively move the
 *  kernel to using SVA for interrupts without completely breaking it.
 */
void
sva_icontext (struct trapframe * tf) {
  /*
   * Fetch the interrupt context.
   */
  sva_icontext_t * p = get_CPUState()->currentIContext;

  /*
   * Store the fields into the trap frame.
   */
  p->rdi = tf->tf_rdi;
  p->rsi = tf->tf_rsi;
  p->rcx = tf->tf_rcx;
  p->r8  = tf->tf_r8;
  p->r9  = tf->tf_r9;
  p->rax = tf->tf_rax;
  p->rbx = tf->tf_rbx;
  p->rbp = tf->tf_rbp;
  p->r10 = tf->tf_r10;
  p->r11 = tf->tf_r11;
  p->r12 = tf->tf_r12;
  p->r13 = tf->tf_r13;
  p->r14 = tf->tf_r14;
  p->r15 = tf->tf_r15;

  p->trapno = tf->tf_trapno;


  p->fs = tf->tf_fs;
  p->gs = tf->tf_gs;
  p->es = tf->tf_es;

  p->code = tf->tf_err;
  p->rip = tf->tf_rip;
  p->cs = tf->tf_cs;
  p->rflags = tf->tf_rflags;
  p->rsp = (unsigned long *)(tf->tf_rsp);
  p->ss = tf->tf_ss;

  return;
}

#if 0
/*
 * Function: llva_icontext()
 *
 * Description:
 *  Convert the state as represented by the Linux pt_regs structure back into
 *  an LLVA exception context structure.
 *
 *  This allows me to hack the exec() system call to work.
 */
void
llva_icontext (void * icontext, struct pt_regs * pt)
{
  llva_icontext_t * p = icontext;

  p->ebx = pt->ebx;
  p->ecx = pt->ecx;
  p->edx = pt->edx;
  p->esi = pt->esi;
  p->edi = pt->edi;
  p->ebp = pt->ebp;
  p->eax = pt->eax;
  p->ds = pt->xds;
  p->es = pt->xes;
  p->eax = pt->eax;
  p->code = pt->orig_eax;
  p->eip = pt->eip;
  p->cs = pt->xcs;
  p->eflags = pt->eflags;
  p->esp = (void *)(pt->esp);
  p->ss = pt->xss;
  return;
}

void *
llva_get_eip (void * icontext)
{
  llva_icontext_t * p = icontext;
  return p->eip;
}

int
llva_print_icontext (void * q)
{
  llva_icontext_t * p = q;
  if (q)
  {
    printk ("<0>" "LLVA: icontext\n");
    printk("<0>eip: 0x%x   esp: 0x%x   ebp: 0x%x \n", p->eip, p->esp, p->ebp);
    printk("<0>eax: 0x%x   ebx: 0x%x   ecx: 0x%x \n", p->eax, p->ebx, p->ecx);
    printk("<0>edx: 0x%x   esi: 0x%x   edi: 0x%x \n", p->edx, p->esi, p->edi);
    printk ("<0>" "LLVA: icontext  cs: 0x%x\n", (p->cs & 0xffff));
    printk ("<0>" "LLVA: icontext  eflags: 0x%x\n", p->eflags);
    printk ("<0>" "LLVA: icontext  code  : 0x%x\n", p->code);
    printk("es: 0x%x   ds: 0x%x   gs: 0x%x \n", p->es, p->ds, p->gs);
    printk ("<0>" "--------------------------------\n", p->eax);
  }
  else
  {
    printk ("<0>" "LLVA: icontext is NULL\n");
  }
  return 0;
}

void
llva_psysnum (int a, int arg1, int arg2, int arg3, int arg4, int arg5, int arg6, void * icontext)
{
  if (current->llva_trace)
  {
    printk ("LLVA: PID %d Syscall %d\n", current->pid, a);
  }
  return;
}

//noop
void llva_assert_match_sig(void* f) {
}
#endif

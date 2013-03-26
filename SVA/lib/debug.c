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

#include <sva/callbacks.h>
#include <sva/config.h>
#include <sva/state.h>
#include <sva/interrupt.h>
#include <machine/frame.h>

/*****************************************************************************
 * Assertion Code
 ****************************************************************************/

void
assertGoodIC (void) {
  /*
   * Get the CPU State and latest Interrupt Context
   */
  struct CPUState * cpup = getCPUState();
  sva_icontext_t * p = getCPUState()->newCurrentIC;

  if ((p < cpup->currentThread->interruptContexts) ||
      (cpup->currentThread->interruptContexts + maxIC < p)) {
    panic ("SVA: Out of Bounds IC: %p %p %p\n", p, cpup->currentThread->interruptContexts, cpup->currentThread->interruptContexts + maxIC);
  }

  return;
}

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
   * Fetch the currently available interrupt context.
   */
  struct CPUState * cpup = getCPUState();
  sva_icontext_t * p = getCPUState()->newCurrentIC;

#if 0
  printf ("SVA: (%p): %p: %p %p\n\n", cpup,
                                      cpup->newCurrentIC,
                                      cpup->interruptContexts + maxIC,
                                      cpup->interruptContexts + maxIC - 1);
#endif

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
  tf->tf_rdx = p->rdx;
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
 * Function: sva_syscall_trapframe()
 *
 * Description:
 *  Convert the state as represented by the Execution Engine back into FreeBSD's
 *  trapframe structure.
 *
 *  The reason for doing this is that it allows me to progressively move the
 *  kernel to using SVA for interrupts without completely breaking it.
 *
 *  This version of the function does some translating between registers.
 */
void
sva_syscall_trapframe (struct trapframe * tf) {
  /*
   * Fetch the currently available interrupt context.
   */
  struct CPUState * cpup = getCPUState();
  sva_icontext_t * p = getCPUState()->newCurrentIC;

#if 0
  printf ("SVA: (%p): %p: %p %p\n\n", cpup,
                                      cpup->newCurrentIC,
                                      cpup->interruptContexts + maxIC,
                                      cpup->interruptContexts + maxIC - 1);
#endif

  /*
   * Store the fields into the trap frame.
   */
  tf->tf_rdi = p->rdi;
  tf->tf_rsi = p->rsi;
  tf->tf_rcx = p->r10;  /* Done for system call ABI */
  tf->tf_r8  = p->r8;
  tf->tf_r9  = p->r9;
  tf->tf_rax = p->rax;
  tf->tf_rbx = p->rbx;
  tf->tf_rdx = p->rdx;
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
  tf->tf_ds = p->ds;

  tf->tf_err = p->code;
  tf->tf_rip = p->rcx;
  tf->tf_cs = p->cs;
  tf->tf_rflags = p->r11;
  tf->tf_rsp = (unsigned long)(p->rsp);
  tf->tf_ss = p->ss;

  return;
}

#if 0
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
   * Fetch the currently free interrupt context.
   */
  sva_icontext_t * p = getCPUState()->newCurrentIC;

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
  p->rcx = tf->tf_rcx;
  p->rdx = tf->tf_rdx;
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
#endif

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
#endif

static void
print_icontext (char * s, sva_icontext_t * p) {
  printf ("rip: 0x%lx   rsp: 0x%lx   rbp: 0x%lx \n", p->rip, p->rsp, p->rbp);
  printf ("rax: 0x%lx   rbx: 0x%lx   rcx: 0x%lx \n", p->rax, p->rbx, p->rcx);
  printf ("rdx: 0x%lx   rsi: 0x%lx   rdi: 0x%lx \n", p->rdx, p->rsi, p->rdi);
  printf ("SVA: icontext  cs: 0x%lx\n", p->cs);
  printf ("SVA: icontext  rflags  : 0x%lx\n", p->rflags);
  printf ("SVA: icontext  code    : 0x%lx\n", p->code);
  printf ("SVA: icontext  trapno  : 0x%lx\n", p->trapno);
  printf ("SVA: icontext  invokep : 0x%lx\n", p->invokep);
  printf ("es: 0x%x   fs: 0x%x    ds: 0x%x   gs: 0x%x \n", p->es, p->fs, p->ds, p->gs);
  printf ("----------------------------------------------------------------\n");
  return;
}

int
sva_print_icontext (char * s) {
  struct CPUState * cpup = getCPUState();
  sva_icontext_t * p = cpup->newCurrentIC;
  printf ("SVA: %s: (%p): %p: %p\n\n", s, cpup,
                                       cpup->newCurrentIC,
                                       cpup->currentThread->interruptContexts + maxIC - 1);
  print_icontext (s, p);
  return 0;
}

void
sva_print_integer (uintptr_t integer) {
  struct SVAThread * thread = (struct SVAThread *)(integer);
  sva_integer_state_t * intp =  thread ? &(thread->integerState) : 0;
  if (!intp) return;
  printf ("SVA: integer: int3: %lx\tkstackp: %lx\n", intp->ist3, intp->kstackp);
  uintptr_t start, field;
  start = (uintptr_t) (thread);
  field = (uintptr_t) &(thread->interruptContexts[maxIC]);
  printf ("SVA: integer: %lx\n", field - start);
  printf ("SVA: integer: sizeof Thread: %lx\n", sizeof (struct SVAThread));
  printf ("SVA: integer: sizeof IC: %lx\n", sizeof (struct sva_icontext));
  return;
}

void
sva_print_ist3 (unsigned long id) {
  struct CPUState * cpup = getCPUState();
  printf ("SVA: %d: ist3 = %p: %lx\n", id, &(cpup->tssp->ist3), cpup->tssp->ist3);
  if (cpup->tssp->ist3 == 0) {
    __asm__ __volatile__ ("xchg %%bx, %%bx\n" :: "a" (id));
  }
  return;
}

void
sva_print_inttable (void) {
  extern void default_interrupt (unsigned int number, void * icontext);
  extern void * interrupt_table[256];
  unsigned index = 0;
  for (unsigned index = 0; index < 256; ++index) {
    if (interrupt_table[index] != default_interrupt)
      printf ("SVA: %d: %lx\n", index, interrupt_table[index]);
  }
  return;
}

#if 0
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

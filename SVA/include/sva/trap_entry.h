#ifndef _TRAP_ENTRY_H_
#define _TRAP_ENTRY_H_

// For better or for worse, 'SVA_MMU'
// kernel option is used to determine
// if we're running as NK or normal FreeBSD.
#ifdef SVA_MMU
#define DISABLE_INTERRUPTS \
  /* ENSURE that interrupts are disabled */ \
  cli;

#define ENABLE_WP_BIT \
  /* Save scratch register to stack */ \
  pushq %rax; \
  /* Get current cr0 value */ \
  movq %cr0, %rax; \
  /* Set WP bit in copy */ \
  orq $0x10000, %rax; \
  /* Replace cr0 with updated value */ \
  movq %rax, %cr0; \
  /* Restore clobbered register */ \
  popq %rax;

#define SECURE_TRAP_ENTRY \
  /* And that WP is enabled! */ \
  DISABLE_INTERRUPTS \
  ENABLE_WP_BIT

#else // !SVA_MMU

#define SECURE_TRAP_ENTRY /* Nothing */

#endif // SVA_MMU

#endif // _TRAP_ENTRY_H_

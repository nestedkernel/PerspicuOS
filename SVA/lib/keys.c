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
char * dummy256KeyPtr = "a2nwP12YVfud1u300wF955JHmHvZ5886";  

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
    /* Put the private key into the thread's key slot */
    strcpy(thread->secret.key, dummy256KeyPtr);
    dummy256KeyPtr[keyI] = uniqueFirstChar++;
    if(uniqueFirstChar == 0x7E) {
        keyI++; uniqueFirstChar = 0x22; 
    } 
#endif
}

/*
 * Function: getSecretFromActiveContext()
 *
 * Description:
 *  This function obtains the app secret from the currently active CPU state.
 *  It then returns a pointer to the secret key object. 
 *
 * Return value:
 *  - A pointer to the key inside the active context's
 *    thread structure.
 */
inline sva_key_t *
getSecretFromActiveContext() {
  return &getCPUState()->currentThread->secret;
}

/*
 * Function: getThreadSecret
 *
 * Description:
 *  This is the trap handler to return a pointer to the active thread's secret
 *  key, when requested by the user mode process. The pointer is obtained from
 *  the active CPU state and placed in the EAX register. Note also the type of
 *  data structure pointed to by the pointer. It is an encapsulated key so that
 *  the representation (length) can change without modifying the interface.
 */
void 
getThreadSecret (void) {
    /*
     * Get the current interrupt context; the arguments will be in it.
     */
    struct CPUState * cpup = getCPUState(); 
    sva_key_t * tSecret = &(cpup->currentThread->secret); 
    sva_icontext_t * icp = cpup->newCurrentIC; 

    /* Set the rax register with the pointer to the secret key */
    icp->rax = (uintptr_t) tSecret;
}

#if 0
/* 
 * FIXME: this function was originally proposed by John for allocating a key.
 * In designing and developing the key management solution it wasn't obvious
 * how this would be used. Therefore, a primitive form is left commented out
 * below. It may be obsolete however given the new design.
 */
sva_key_t appKeys[100];
uint64_t keyIndex = 0; 

/*
 * Function: sva_translate
 *
 * Description: This function is responsible for allocating space for
 *  application keys and putting the key into the recently allocated region.
 *
 */
void
sva_translate(){

    /* Copy the key into the pointer for the key */
    strcpy(appKeys[keyIndex].key, dummy256KeyPtr);
#if DEBUG
    printf("The new key value: %s, The current index: %llu\n",
            appKeys[keyIndex].key, keyIndex); 
#endif
    /* 
     * Increment the key so that the next time we get a request we store a new
     * key.
     */
    keyIndex++;
}
#endif

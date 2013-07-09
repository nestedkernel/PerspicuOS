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

#DEBUG 1

/* 
 * TODO: Modify this so that it puts the key into some type of app specific
 * container. 
 */

/* Default key value and data structures storing the keys */
static const char * dummy256KeyPtr = "p2nwP12YVfud1u300wF955JHmHvZ5886";  
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

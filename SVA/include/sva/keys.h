/*===- keys.h - SVA Execution Engine  =------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *
 *===----------------------------------------------------------------------===
 *
 *       Filename:  keys.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  07/07/13 23:08:35
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Nathan Dautenhahn (nathandautenhahn.com), dautenh1@illinois.edu
 *        Company:  University of Illinois at Urbana-Champaign
 *
 * ===========================================================================
 */


#ifndef SVA_KEYS_H
#define SVA_KEYS_H

/* Type representing a key */
//typedef char sva_key_t;

typedef struct sva_key_t{
    char key[256];
} sva_key_t;

#endif /* SVA_KEYS_H */

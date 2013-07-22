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
 *         Author:  Nathan Dautenhahn (nathandautenhahn.com),
 *                                     dautenh1@illinois.edu
 *        Company:  University of Illinois at Urbana-Champaign
 *
 * ===========================================================================
 */

#ifndef SVA_KEYS_H
#define SVA_KEYS_H

/*
 *****************************************************************************
 * Define structures used in SVA for key managment
 *****************************************************************************
 */

/* 
 * Structure: sva_key_t
 *
 * Description: encapsulates an sva key, which is a character array.
 */
typedef struct sva_key_t {
    char key[16];
} sva_key_t;

/*
 * Structure: translation
 *
 * Description:
 *  Record information about SVA bitcode to native code translations.
 */
struct translation {
  /* Private key of the translated program */
  sva_key_t key;

  /* Entry point for the translated program */
  void * entryPoint;

  /* Flag indiating whether entry is in use */
  unsigned char used;
};

/*
 *****************************************************************************
 * Define functions used in the SVA key management interface
 *****************************************************************************
 */
inline sva_key_t * getSecretFromActiveContext();
void getThreadSecret (void);

/*
 *****************************************************************************
 * Globals shared amount compilation units.
 *****************************************************************************
 */

/* Array of cached translations */
extern struct translation translations [4096];

#endif /* SVA_KEYS_H */

/*===- ughost.h - Virtual Ghost User-space Utilities ----------------------===
 * 
 *                     The LLVM Compiler Infrastructure
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This header files defines functions and macros used by applications.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef _SVA_UESRGHOST_H
#define _SVA_UESRGHOST_H

/*
 * Function: sva_get_key()
 *
 * Description:
 *  Return the location within ghost memory at which SVA has placed the
 *  application's private key.
 */
static inline unsigned char *
sva_get_key (void) {
  /* Pointer to the key */
  unsigned char * keyp;
  __asm__ __volatile__ ("int $0x7c\n" : "=a" (keyp));
  return keyp;
}
#endif

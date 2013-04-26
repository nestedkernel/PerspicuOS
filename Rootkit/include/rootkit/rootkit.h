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

/* Rootkit attack types */
static const unsigned char at_read = 1;   /* Direct read attack */
static const unsigned char at_mmu  = 2;   /* MMU attack */
static const unsigned char at_sig  = 3;   /* Signal handler attack */


/*===- callbacks.h - SVA Execution Engine  =--------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file defines functions that the system software (operating system or
 * hypervisor) must implement to support the SVA VM.
 *
 */

#ifndef SVA_CALLBACKS_H
#define SVA_CALLBACKS_H

#include <sys/types.h>

/* Kernel callback function for allocating memory */
extern uintptr_t provideSVAMemory (uintptr_t size);
extern void releaseSVAMemory (uintptr_t, uintptr_t size);

/* These callbacks are used for debugging and assertions */
extern int printf(const char *, ...);
extern int panic(const char *, ...);

#endif

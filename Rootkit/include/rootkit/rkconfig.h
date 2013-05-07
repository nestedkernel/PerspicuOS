/*===- rkconfig.h - Example Rootkit =---------------------------------------===
 * 
 *                        Example Virtual Ghost Rootkit
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file defines configuration parameters for our example rootkit.
 *
 *===----------------------------------------------------------------------===
 */

#if 0
/* Define the target address containing the data that we want to steal */
#if 1
/* Traditional version */
#define TARGET 0x800808040
#else
/* Ghost version */
#define TARGET 0xffffff0000808040
#endif

/* Define the size of the data that we want to steal */
#define SIZE 0x3

/* Define the file descriptor to which the stolen data should be written */
#define FD 0x1
#else
#define TARGET 0x4247e0
#define SIZE 0xb
#define FD 0x1
#endif



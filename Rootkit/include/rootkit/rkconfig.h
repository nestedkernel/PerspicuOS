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

/* Define the target address containing the data that we want to steal */
#define TARGET 0x425860

/* Define the size of the data that we want to steal */
#define SIZE 0xc

/* Define the file descriptor to which the stolen data should be written */
#define FD 0x1



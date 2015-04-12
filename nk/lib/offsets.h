/*===- offsets.h - SVA Execution Engine Assembly ---------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===----------------------------------------------------------------------===
 *
 * This file defines the offsets of fields in SVA data structures.  It is
 * primarily designed for assembly code that accesses these data structures.
 *
 *===----------------------------------------------------------------------===
 */

/* Offsets for various fields in the SVA Interrupt Context */
#define IC_INVOKEP 0x00
#define IC_FS      0x08
#define IC_GS      0x0a
#define IC_ES      0x0c
#define IC_DS      0x0e

#define IC_RDI     0x10
#define IC_RSI     0x18

#define IC_RAX     0x20
#define IC_RBX     0x28
#define IC_RCX     0x30
#define IC_RDX     0x38

#define IC_R8      0x40
#define IC_R9      0x48
#define IC_R10     0x50
#define IC_R11     0x58
#define IC_R12     0x60
#define IC_R13     0x68
#define IC_R14     0x70
#define IC_R15     0x78

#define IC_RBP     0x80

#define IC_TRAPNO  0x88

#define IC_CODE    0x90
#define IC_RIP     0x98
#define IC_CS      0xa0
#define IC_RFLAGS  0xa8
#define IC_RSP     0xb0
#define IC_SS      0xb8

#define IC_VALID   0xc0
#define IC_FPP     0xc8

/* Size of the interrupt context */
#define IC_SIZE    0xd0

#define IS_HACKRIP 0xc8

/* Offsets for various fields in the CPU State Structure */
#define CPU_THREAD 0x00
#define CPU_TSSP   0x08
#define CPU_NEWIC  0x10
#define CPU_GIP    0x18

/* Offsets into the Task State Segment */
#define TSS_RSP0 4
#define TSS_IST3 52

/* Types of Invoke Frames */
#define INVOKE_NORMAL   0
#define INVOKE_MEMCPY_W 1
#define INVOKE_MEMCPY_B 2
#define INVOKE_STRNCPY  3
#define INVOKE_MEMSET   2


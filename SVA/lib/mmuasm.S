/*===- mmuasm.S - SVA Execution Engine Assembly ---------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===----------------------------------------------------------------------===
 *
 * This is x86_64 assembly code used by the SVA Execution Engine.
 * It is in AT&T syntax, which means that the source operand is first and
 * the destination operand is second.
 *
 * This purpose of this file is to define some things needed by the MMU code
 * that seem to be best done in assembly.
 *
 *===----------------------------------------------------------------------===
 */

/*
 * Global: SVAPTPages
 *
 * Description:
 *  This defines a global symbol, aligned on a page boundary, that is an array
 *  of page table pages that SVA can use.
 *
 * Notes:
 *  We define this here because the align directive in Clang 3.0 doesn't seem
 *  to force 4096-byte alignment like it should.  This directive works.
 */
.comm SVAPTPages, 262144, 4096


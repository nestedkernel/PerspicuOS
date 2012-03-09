# $FreeBSD: release/9.0.0/lib/libc/sparc64/Makefile.inc 174204 2007-12-03 07:17:33Z das $
#
# Machine dependent definitions for the ultra sparc architecture.
#

.include "fpu/Makefile.inc"

# Long double is quad precision
GDTOASRCS+=strtorQ.c
MDSRCS+=machdep_ldisQ.c
SYM_MAPS+=${.CURDIR}/sparc64/Symbol.map

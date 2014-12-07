# $FreeBSD: release/9.0.0/lib/libc/powerpc64/Makefile.inc 209878 2010-07-10 14:45:03Z nwhitehorn $

# Long double is 64-bits
MDSRCS+=machdep_ldisd.c
SYM_MAPS+=${.CURDIR}/powerpc64/Symbol.map

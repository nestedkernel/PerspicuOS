# $FreeBSD: release/9.0.0/lib/libthread_db/Makefile 211725 2010-08-23 22:24:11Z imp $

.PATH:	${.CURDIR}/arch/${MACHINE_CPUARCH}

LIB=	thread_db
SHLIB_MAJOR= 3
SRCS=	thread_db.c
SRCS+=	libpthread_md.c
SRCS+=	libpthread_db.c
SRCS+=	libthr_db.c
INCS=	thread_db.h

CFLAGS+=-I. -I${.CURDIR}
SYM_MAPS+=${.CURDIR}/Symbol.map

SYMBOL_MAPS=${SYM_MAPS}
VERSION_DEF=${.CURDIR}/../libc/Versions.def

.include <bsd.lib.mk>

# $FreeBSD: release/9.0.0/usr.bin/minigzip/Makefile 205472 2010-03-22 21:19:17Z delphij $

SRCDIR=	${.CURDIR}/../../lib/libz
.PATH:	${SRCDIR}

PROG=	minigzip

WARNS?=	5
CFLAGS+=-DUSE_MMAP
DPADD=	${LIBZ}
LDADD=	-lz

.include <bsd.prog.mk>

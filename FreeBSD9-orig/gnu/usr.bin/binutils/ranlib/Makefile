# $FreeBSD: release/9.0.0/gnu/usr.bin/binutils/ranlib/Makefile 176737 2008-03-02 11:10:46Z ru $

.include "../Makefile.inc0"

.PATH: ${SRCDIR}/binutils ${SRCDIR}/binutils/doc

PROGNAME= gnu-ranlib
MAN=	gnu-ranlib.1
gnu-ranlib.1: ranlib.1
	cat ${.ALLSRC} > ${.TARGET}
CLEANFILES+= gnu-ranlib.1

PROG=	ranlib
SRCS=	ar.c is-ranlib.c
CFLAGS+= -D_GNU_SOURCE
CFLAGS+= -I${.CURDIR}/${RELTOP}/libbinutils
CFLAGS+= -I${SRCDIR}/binutils
CFLAGS+= -I${SRCDIR}/bfd
NO_SHARED?= yes
DPADD=	${RELTOP}/libbinutils/libbinutils.a
DPADD+=	${RELTOP}/libbfd/libbfd.a
DPADD+=	${RELTOP}/libiberty/libiberty.a
LDADD=	${DPADD}

.include <bsd.prog.mk>

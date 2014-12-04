# $FreeBSD: release/9.0.0/usr.bin/ar/Makefile 208189 2010-05-17 09:37:59Z kaiw $

PROG=	ar
SRCS=	ar.c acplex.l acpyacc.y read.c util.c write.c y.tab.h

DPADD=	${LIBARCHIVE} ${LIBELF}
LDADD=	-larchive -lelf

CFLAGS+=-I. -I${.CURDIR}

NO_SHARED?=	yes
LINKS=	${BINDIR}/ar ${BINDIR}/ranlib
MLINKS= ar.1 ranlib.1

.include <bsd.prog.mk>

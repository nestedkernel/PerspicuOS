# $FreeBSD: release/9.0.0/usr.sbin/tzsetup/Makefile 217309 2011-01-12 14:55:02Z nwhitehorn $

PROG=	tzsetup
MAN=	tzsetup.8

CFLAGS+= -I${.CURDIR}/../../gnu/lib/libodialog -I.

WARNS?=	3

DPADD=	${LIBODIALOG} ${LIBNCURSES}
LDADD=	-lodialog -lncurses

.include <bsd.prog.mk>

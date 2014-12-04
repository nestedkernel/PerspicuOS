# $FreeBSD: release/9.0.0/sbin/iscontrol/Makefile 211095 2010-08-09 12:36:36Z des $

SRCS= iscontrol.c pdu.c fsm.c config.c login.c auth_subr.c misc.c
PROG= iscontrol
DPADD= ${LIBCAM} ${LIBMD}
LDADD= -lcam -lmd
S= ${.CURDIR}/../../sys

WARNS?=	3
CFLAGS += -I$S
#CFLAGS += -g -DDEBUG

MAN= iscsi.conf.5 iscontrol.8

.include <bsd.prog.mk>

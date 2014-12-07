# $FreeBSD: release/9.0.0/sys/modules/cxgb/toecore/Makefile 184950 2008-11-14 01:56:11Z ps $

CXGB = ${.CURDIR}/../../../dev/cxgb
.PATH: ${CXGB}/ulp/toecore

KMOD=	toecore
SRCS=   toedev.c
SRCS+=	device_if.h bus_if.h pci_if.h opt_sched.h opt_inet.h
CFLAGS+= -g -I${CXGB}

.include <bsd.kmod.mk>

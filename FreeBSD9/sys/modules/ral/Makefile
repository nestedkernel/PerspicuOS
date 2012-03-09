# $FreeBSD: release/9.0.0/sys/modules/ral/Makefile 178354 2008-04-20 20:35:46Z sam $

.PATH: ${.CURDIR}/../../dev/ral

KMOD=	if_ral
SRCS=	rt2560.c rt2661.c if_ral_pci.c
SRCS+=	device_if.h bus_if.h pci_if.h

.include <bsd.kmod.mk>

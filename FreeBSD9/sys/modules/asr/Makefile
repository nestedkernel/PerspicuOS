# $FreeBSD: release/9.0.0/sys/modules/asr/Makefile 211690 2010-08-23 06:13:29Z imp $

.PATH: ${.CURDIR}/../../dev/asr

KMOD=	asr
SRCS=	asr.c
SRCS+=	opt_scsi.h opt_cam.h
SRCS+=	device_if.h bus_if.h pci_if.h

.if ${MACHINE_CPUARCH} == "i386"
SRCS+=	opt_asr.h
.endif

.include <bsd.kmod.mk>

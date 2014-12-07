# $FreeBSD: release/9.0.0/sys/modules/cmx/Makefile 176868 2008-03-06 08:09:45Z rink $
#
MAINTAINER=	daniel@roe.ch

.PATH:	${.CURDIR}/../../dev/cmx

KMOD=	cmx
SRCS=	cmx.c cmxvar.h cmxreg.h \
	cmx_pccard.c \
	pccarddevs.h device_if.h bus_if.h card_if.h

.include <bsd.kmod.mk>

# $FreeBSD: release/9.0.0/sys/modules/geom/geom_raid/Makefile 219974 2011-03-24 21:31:32Z mav $

.PATH: ${.CURDIR}/../../../geom/raid

KMOD=	geom_raid
SRCS=	g_raid.c
SRCS+=	g_raid_ctl.c
SRCS+=	bus_if.h device_if.h
SRCS+=	g_raid_md_if.h g_raid_md_if.c
SRCS+=	g_raid_tr_if.h g_raid_tr_if.c

SRCS+=	md_intel.c md_jmicron.c md_nvidia.c md_promise.c md_sii.c

SRCS+=	tr_concat.c tr_raid0.c tr_raid1.c tr_raid1e.c

MFILES=	kern/bus_if.m kern/device_if.m
MFILES+= geom/raid/g_raid_md_if.m geom/raid/g_raid_tr_if.m

.include <bsd.kmod.mk>

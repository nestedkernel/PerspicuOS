# $FreeBSD: release/9.0.0/sys/modules/mlx4ib/Makefile 219820 2011-03-21 09:58:24Z jeff $
.PATH:  ${.CURDIR}/../../ofed/drivers/infiniband/hw/mlx4
KMOD    = mlx4ib
SRCS    = device_if.h bus_if.h pci_if.h vnode_if.h
SRCS+=	ah.c cq.c doorbell.c mad.c main.c mr.c qp.c srq.c wc.c

CFLAGS+= -I${.CURDIR}/../../ofed/include/ -DINET6

.include <bsd.kmod.mk>

CFLAGS+= -Wno-cast-qual -Wno-pointer-arith -fms-extensions

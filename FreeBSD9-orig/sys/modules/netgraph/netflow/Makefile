# $FreeBSD: release/9.0.0/sys/modules/netgraph/netflow/Makefile 219182 2011-03-02 16:15:11Z glebius $
#
# Author: Gleb Smirnoff <glebius@freebsd.org>
#

.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../../netgraph/netflow

KMOD=   ng_netflow
SRCS=   ng_netflow.c netflow.c netflow_v9.c opt_inet6.h opt_route.h

.if !defined(KERNBUILDDIR)

.if ${MK_INET6_SUPPORT} != "no"
opt_inet6.h:
	echo "#define INET6 1" > ${.TARGET}
.endif

opt_route.h:
	echo "#define ROUTETABLES RT_MAXFIBS" > ${.TARGET}
.endif

.include <bsd.kmod.mk>

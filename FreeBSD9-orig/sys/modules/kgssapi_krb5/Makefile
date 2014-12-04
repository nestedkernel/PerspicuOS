# $FreeBSD: release/9.0.0/sys/modules/kgssapi_krb5/Makefile 223309 2011-06-19 22:08:55Z rmacklem $

.PATH: ${.CURDIR}/../../kgssapi/krb5
KMOD=	kgssapi_krb5

SRCS=	krb5_mech.c \
	kcrypto.c \
	kcrypto_des.c \
	kcrypto_des3.c \
	kcrypto_aes.c \
	kcrypto_arcfour.c \
	opt_inet6.h

SRCS+=		kgss_if.h gssd.h
MFILES=		kgssapi/kgss_if.m

S=		${.CURDIR}/../..

gssd.h:		$S/kgssapi/gssd.x
	rpcgen -hM $S/kgssapi/gssd.x | grep -v pthread.h > gssd.h

.include <bsd.kmod.mk>

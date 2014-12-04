# $FreeBSD: release/9.0.0/usr.bin/fetch/Makefile 204352 2010-02-26 09:41:16Z ru $

.include <bsd.own.mk>

PROG=		fetch
CSTD?=		c99
DPADD=		${LIBFETCH} ${LIBMD}
LDADD=		-lfetch -lmd
.if ${MK_OPENSSL} != "no"
DPADD+=		${LIBSSL} ${LIBCRYPTO}
LDADD+=		-lssl -lcrypto
.endif

.include <bsd.prog.mk>

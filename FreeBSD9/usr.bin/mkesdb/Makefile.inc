# $FreeBSD: release/9.0.0/usr.bin/mkesdb/Makefile.inc 219019 2011-02-25 00:04:39Z gabor $

SRCS+=	lex.l yacc.y
CFLAGS+= -I${.CURDIR} -I${.CURDIR}/../mkesdb \
	 -I${.CURDIR}/../../lib/libc/iconv \
	 --param max-inline-insns-single=64

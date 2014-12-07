# $FreeBSD: release/9.0.0/usr.bin/mkcsmapper/Makefile.inc 219019 2011-02-25 00:04:39Z gabor $

SRCS+=	lex.l yacc.y
CFLAGS+= -I${.CURDIR} -I${.CURDIR}/../mkcsmapper \
	 -I${.CURDIR}/../../lib/libc/iconv \
	 -I${.CURDIR}/../../lib/libiconv_modules/mapper_std \
	 --param max-inline-insns-single=64

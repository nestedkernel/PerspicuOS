#	@(#)Makefile	8.1 (Berkeley) 6/4/93
# $FreeBSD: release/9.0.0/libexec/tftpd/Makefile 213099 2010-09-24 10:40:17Z marius $

PROG=	tftpd
MAN=	tftpd.8
SRCS=	tftp-file.c tftp-io.c tftp-options.c tftp-transfer.c tftp-utils.c
SRCS+=	tftpd.c
WFORMAT=0
LDFLAGS= -lwrap

.include <bsd.prog.mk>

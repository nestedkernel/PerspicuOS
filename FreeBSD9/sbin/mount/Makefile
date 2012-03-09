#	@(#)Makefile	8.6 (Berkeley) 5/8/95
# $FreeBSD: release/9.0.0/sbin/mount/Makefile 198236 2009-10-19 16:00:24Z ru $

PROG=	mount
SRCS=	mount.c mount_fs.c getmntopts.c vfslist.c
MAN=	mount.8
# We do NOT install the getmntopts.3 man page.

DPADD=	${LIBUTIL}
LDADD=	-lutil

.include <bsd.prog.mk>

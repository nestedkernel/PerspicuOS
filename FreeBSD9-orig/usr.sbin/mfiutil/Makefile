# $FreeBSD: release/9.0.0/usr.sbin/mfiutil/Makefile 204329 2010-02-25 20:24:19Z ru $
PROG=	mfiutil

SRCS=	mfiutil.c mfi_cmd.c mfi_config.c mfi_drive.c mfi_evt.c mfi_flash.c \
	mfi_patrol.c mfi_show.c mfi_volume.c
MAN8=	mfiutil.8

CFLAGS+= -fno-builtin-strftime
WARNS?=3

DPADD=	${LIBUTIL}
LDADD=	-lutil

# Here be dragons
.ifdef DEBUG
CFLAGS+= -DDEBUG
.endif

.include <bsd.prog.mk>

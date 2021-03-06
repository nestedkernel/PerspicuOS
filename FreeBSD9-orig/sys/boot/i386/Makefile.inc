# Common defines for all of /sys/boot/i386/
#
# $FreeBSD: release/9.0.0/sys/boot/i386/Makefile.inc 224131 2011-07-17 13:50:21Z dim $

BINDIR?=	/boot

LOADER_ADDRESS?=0x200000
CFLAGS+=	-ffreestanding -mpreferred-stack-boundary=2 \
		-mno-mmx -mno-3dnow -mno-sse -mno-sse2 -mno-sse3 -msoft-float
LDFLAGS+=	-nostdlib

.if ${MACHINE_CPUARCH} == "amd64"
CFLAGS+=	-m32 -march=i386
ACFLAGS+=	-m32
LDFLAGS+=	-m elf_i386_fbsd
AFLAGS+=	--32
.endif

# BTX components
.if exists(${.OBJDIR}/../btx)
BTXDIR=		${.OBJDIR}/../btx
.else
BTXDIR=		${.CURDIR}/../btx
.endif
BTXLDR=		${BTXDIR}/btxldr/btxldr
BTXKERN=	${BTXDIR}/btx/btx
BTXCRT=		${BTXDIR}/lib/crt0.o

.include "../Makefile.inc"

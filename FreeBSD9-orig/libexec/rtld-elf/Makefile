# $FreeBSD: release/9.0.0/libexec/rtld-elf/Makefile 225152 2011-08-24 20:05:13Z kib $

.include <bsd.own.mk>
MK_SSP=		no

PROG?=		ld-elf.so.1
SRCS=		rtld_start.S \
		reloc.c rtld.c rtld_lock.c rtld_printf.c map_object.c \
		malloc.c xmalloc.c debug.c libmap.c
MAN=		rtld.1
CSTD?=		gnu99
CFLAGS+=	-Wall -DFREEBSD_ELF -DIN_RTLD
.if exists(${.CURDIR}/${MACHINE_ARCH})
RTLD_ARCH=	${MACHINE_ARCH}
.else
RTLD_ARCH=	${MACHINE_CPUARCH}
.endif
CFLAGS+=	-I${.CURDIR}/${RTLD_ARCH} -I${.CURDIR}
.if ${MACHINE_ARCH} == "powerpc64"
CFLAGS+=	-mcall-aixdesc
LDFLAGS+=	-nostdlib -e _rtld_start
.else
LDFLAGS+=	-nostdlib -e .rtld_start
.endif
WARNS?=		2
INSTALLFLAGS=	-C -b
PRECIOUSPROG=
BINDIR=		/libexec
SYMLINKS=	${BINDIR}/${PROG} /usr/libexec/${PROG}
MLINKS=		rtld.1 ld-elf.so.1.1 \
		rtld.1 ld.so.1

.if ${MACHINE_CPUARCH} == "sparc64"
CFLAGS+=	-fPIC
.else
CFLAGS+=	-fpic
.endif
CFLAGS+=	-DPIC $(DEBUG)
LDFLAGS+=	-shared -Wl,-Bsymbolic
DPADD=		${LIBC_PIC}
LDADD=		-lc_pic -lssp_nonshared

.if ${MK_SYMVER} == "yes"
LIBCDIR=	${.CURDIR}/../../lib/libc
VERSION_DEF=	${LIBCDIR}/Versions.def
SYMBOL_MAPS=	${.CURDIR}/Symbol.map
VERSION_MAP=	Version.map
LDFLAGS+=	-Wl,--version-script=${VERSION_MAP}

${PROG}:	${VERSION_MAP}

.if exists(${.CURDIR}/${RTLD_ARCH}/Symbol.map)
SYMBOL_MAPS+=	${.CURDIR}/${RTLD_ARCH}/Symbol.map
.endif
.endif

.sinclude "${.CURDIR}/${RTLD_ARCH}/Makefile.inc"

# Since moving rtld-elf to /libexec, we need to create a symlink.
# Fixup the existing binary that's there so we can symlink over it.
beforeinstall:
.if exists(${DESTDIR}/usr/libexec/${PROG})
	-chflags noschg ${DESTDIR}/usr/libexec/${PROG}
.endif

.PATH: ${.CURDIR}/${RTLD_ARCH}

.include <bsd.symver.mk>
.include <bsd.prog.mk>

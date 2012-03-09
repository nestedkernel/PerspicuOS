# $FreeBSD: release/9.0.0/usr.bin/clang/clang.prog.mk 208963 2010-06-09 19:32:20Z rdivacky $

LLVM_SRCS=${.CURDIR}/../../../contrib/llvm

.include "../../lib/clang/clang.build.mk"

.for lib in ${LIBDEPS}
DPADD+= ${.OBJDIR}/../../../lib/clang/lib${lib}/lib${lib}.a
LDADD+= ${.OBJDIR}/../../../lib/clang/lib${lib}/lib${lib}.a
.endfor

BINDIR?=/usr/bin

.include <bsd.prog.mk>

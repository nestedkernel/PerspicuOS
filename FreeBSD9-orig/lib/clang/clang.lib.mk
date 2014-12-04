# $FreeBSD: release/9.0.0/lib/clang/clang.lib.mk 208963 2010-06-09 19:32:20Z rdivacky $

LLVM_SRCS=${.CURDIR}/../../../contrib/llvm

.include "clang.build.mk"

INTERNALLIB=

.include <bsd.lib.mk>

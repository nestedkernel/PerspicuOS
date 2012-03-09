# $FreeBSD: release/9.0.0/usr.bin/clang/clang-tblgen/Makefile 226633 2011-10-22 14:08:43Z dim $

PROG_CXX=clang-tblgen
NO_MAN=

SRCDIR=	tools/clang/utils/TableGen
SRCS=	ClangASTNodesEmitter.cpp \
	ClangAttrEmitter.cpp \
	ClangDiagnosticsEmitter.cpp \
	ClangSACheckersEmitter.cpp \
	NeonEmitter.cpp \
	OptParserEmitter.cpp \
	TableGen.cpp
LLVM_REQUIRES_EH=

LIBDEPS=llvmtablegen llvmsupport

.include "../clang.prog.mk"

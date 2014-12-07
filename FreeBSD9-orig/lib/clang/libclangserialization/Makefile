# $FreeBSD: release/9.0.0/lib/clang/libclangserialization/Makefile 226890 2011-10-28 21:08:39Z dim $

LIB=	clangserialization

SRCDIR=	tools/clang/lib/Serialization
SRCS=	ASTCommon.cpp \
	ASTReader.cpp \
	ASTReaderDecl.cpp \
	ASTReaderStmt.cpp \
	ASTWriter.cpp \
	ASTWriterDecl.cpp \
	ASTWriterStmt.cpp \
	ChainedIncludesSource.cpp \
	GeneratePCH.cpp \
	Module.cpp \
	ModuleManager.cpp

TGHDRS=	AttrList \
	AttrPCHRead \
	AttrPCHWrite \
	Attrs \
	DeclNodes \
	DiagnosticCommonKinds \
	DiagnosticFrontendKinds \
	DiagnosticSemaKinds \
	StmtNodes

.include "../clang.lib.mk"

# $FreeBSD: release/9.0.0/lib/clang/libclangarcmigrate/Makefile 226890 2011-10-28 21:08:39Z dim $

LIB=	clangarcmigrate

SRCDIR=	tools/clang/lib/ARCMigrate
SRCS=	ARCMT.cpp \
	ARCMTActions.cpp \
	FileRemapper.cpp \
	PlistReporter.cpp \
	TransAPIUses.cpp \
	TransARCAssign.cpp \
	TransAutoreleasePool.cpp \
	TransBlockObjCVariable.cpp \
	TransEmptyStatementsAndDealloc.cpp \
	TransformActions.cpp \
	Transforms.cpp \
	TransProperties.cpp \
	TransRetainReleaseDealloc.cpp \
	TransUnbridgedCasts.cpp \
	TransUnusedInitDelegate.cpp \
	TransZeroOutPropsInDealloc.cpp

TGHDRS=	AttrList \
	Attrs \
	DeclNodes \
	DiagnosticCommonKinds \
	DiagnosticGroups \
	DiagnosticSemaKinds \
	StmtNodes

.include "../clang.lib.mk"

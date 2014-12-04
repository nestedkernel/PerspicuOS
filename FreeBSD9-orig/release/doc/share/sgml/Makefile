# $FreeBSD: release/9.0.0/release/doc/share/sgml/Makefile 166778 2007-02-16 02:10:12Z bmah $

RELN_ROOT?= ${.CURDIR}/../..

.include "${RELN_ROOT}/share/mk/doc.relnotes.mk"
.include "${DOC_PREFIX}/share/mk/doc.project.mk"

dev-auto.sgml: ${MAN4PAGES} ${ARCHLIST} ${MAN2HWNOTES_CMD} catalog-auto
	${PERL} ${MAN2HWNOTES_CMD} ${MAN2HWNOTES_FLAGS} -a ${ARCHLIST} -o ${.TARGET} ${MAN4PAGES}

catalog-auto:
	${ECHO_CMD} 'PUBLIC "-//FreeBSD//ENTITIES Auto Generated Device Lists//EN"' \
		'"dev-auto.sgml"' > ${.TARGET}

all: dev-auto.sgml

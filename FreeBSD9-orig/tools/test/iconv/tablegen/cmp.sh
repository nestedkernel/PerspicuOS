#!/bin/sh
# $FreeBSD: release/9.0.0/tools/test/iconv/tablegen/cmp.sh 219019 2011-02-25 00:04:39Z gabor $

diff -I\$FreeBSD: release/9.0.0/tools/test/iconv/tablegen/cmp.sh 219019 2011-02-25 00:04:39Z gabor $1 $2 | grep '^-' >/dev/null && printf "\tDIFFER: $1 $2\n" && exit 0 || exit 0

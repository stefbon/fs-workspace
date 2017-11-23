#!/bin/sh
LIBTOOLIZE=`which libtoolize || which glibtoolize`

$LIBTOOLIZE
aclocal
autoheader
automake --add-missing --copy
autoconf

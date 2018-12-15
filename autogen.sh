#!/bin/sh

set -e # exit on errors

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

olddir=`pwd`
cd "$srcdir"

test ! -d m4 && mkdir m4

autoreconf --verbose --force --install

cd "$olddir"
if [ -z "$NOCONFIGURE" ]; then
    "$srcdir"/configure ${1+"$@"}
fi

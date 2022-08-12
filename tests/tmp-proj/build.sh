#!/bin/bash -eu
$CC $CFLAGS -o "$OUT/fuzz" $LIB_FUZZING_ENGINE temp.c -I$SRC/

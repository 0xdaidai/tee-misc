#!/bin/sh
export COMPILE_PATH=../rootfs/
# export LD_LIBRARY_PATH=$COMPILE_PATH/usr/lib:$COMPILE_PATH/lib
aarch64-linux-gnu-gcc exp.c -o exp -lteec -L $COMPILE_PATH/usr/lib
    #  -Wl,--dynamic-linker=$COMPILE_PATH/lib/ld.soaaaaaa \
    #  -Wl,-rpath-link $COMPILE_PATH/lib/ \

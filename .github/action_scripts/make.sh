#! /bin/bash

DIR=$(cd "$(dirname "$0")";pwd)

git submodule update --init --recursive
cd $DIR/../../thirdparty/watchpoint-lib && make install PREFIX=$DIR/../../build/thirdparty
cd $DIR/../../thirdparty/xed && ./mfile.py --debug --shared --prefix=$DIR/../../build/thirdparty install
cd $DIR/../../thirdparty/libpfm-4.10.1 &&  make PREFIX=$DIR/../../build/thirdparty install
#!/bin/sh
cp /data/gallile/pers_hook/hook.so /data/gallile/fuzzing/
ROOT=$HOME
AFL=/data/gallile/AFLplusplus
DATA=/data/gallile/fuzzing
echo "Synching stuff to home dir"
rsync -rP $DATA/. $ROOT/fuzzing

echo "Installing AFL to home dir"
cd $AFL
export PREFIX=$ROOT/afl
PREFIX=$ROOT/afl make install
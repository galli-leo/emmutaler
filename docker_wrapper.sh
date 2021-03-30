#!/bin/bash
echo "Running $@ inside docker container!"
DIR="/Users/leonardogalli/Code/ETH/thesis/emmutaler"
SYSROOT="/Volumes/cross-build/aarch64/aarch64-unknown-linux-gnu/sysroot"
PARENT="$(dirname "$DIR")"
RELPATH=$(realpath --relative-to="$PARENT" $1)
echo "Mapping $PARENT -> /app"
echo "Running /app/$RELPATH"
shift
DEBUG_ARGS=""
for i in "$@" ; do
    if [[ $i == "debug" ]] ; then
        DEBUG_ARGS="-p 1234:1234 -e QEMU_GDB=1234"
        break
    fi
done
echo "Debug ARGS: $DEBUG_ARGS"
echo "Running: docker run --rm -p 1234:1234 -v $PARENT:/app -v $SYSROOT:/sysroot $DEBUG_ARGS emmu-run $RELPATH $@"
# TODO automatic debugging
docker run --rm -v $PARENT:/app -v $SYSROOT:/sysroot -e QEMU_LD_PREFIX=/sysroot $DEBUG_ARGS emmu-run $RELPATH $@
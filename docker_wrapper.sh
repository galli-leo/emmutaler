#!/bin/bash
echo "Running $@ inside docker container!"
DIR="/Users/leonardogalli/Code/ETH/thesis/emmutaler"
PARENT="$(dirname "$DIR")"
RELPATH=$(realpath --relative-to="$PARENT" $1)
echo "Mapping $PARENT -> /app"
echo "Running /app/$RELPATH"
shift
echo "Running: docker run --rm -p 1234:1234 -v $PARENT:/app emmu-run $RELPATH $@"
docker run --rm -p 1234:1234 -v $PARENT:/app emmu-run $RELPATH $@
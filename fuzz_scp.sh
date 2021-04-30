#!/bin/bash

HOST=$1
USER=$2
DIR=$3
echo "Copying over stuff for fuzzing"
BASE_DEST="$USER@$HOST:$DIR"

IMG_DIR=$5
echo "Running scp $IMG_DIR/*.img4 "$BASE_DEST/img""
#scp $IMG_DIR/*.img4 "$BASE_DEST/img"

for i in "${@:6}"
do
    FILE="$i"
    echo "Running scp $FILE $BASE_DEST"
    scp $FILE $BASE_DEST
done



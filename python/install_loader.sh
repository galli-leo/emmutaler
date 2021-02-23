#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"


function do_link() {
    rm $2
    echo "Installing link $2 -> $1"
    ln -s $1 $2
}

IDA_PATH="${IDA_PATH:-$HOME/.idapro/}"
echo "Installing into $IDA_PATH"
PYTHON_DIR="${IDA_PATH}/python"
LOADERS_DIR="${IDA_PATH}/loaders"
mkdir $LOADERS_DIR || true

ORIG_LOADER="$DIR/scripts/emmu_loader.py"
NEW_LOADER="$LOADERS_DIR/emmu_loader.py"
do_link $ORIG_LOADER $NEW_LOADER

ORIG_DIR="$DIR/emmutaler"
NEW_DIR="$PYTHON_DIR/emmutaler"
do_link $ORIG_DIR $NEW_DIR
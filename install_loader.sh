#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"


IDA_PATH="${IDA_PATH:-$HOME/.idapro/}"
echo "Installing into $IDA_PATH"
PYTHON_DIR="${IDA_PATH}/python"
LOADERS_DIR="${IDA_PATH}/loaders"
mkdir $LOADERS_DIR || true

ORIG_LOADER="$DIR/loader/emmu_loader.py"
NEW_LOADER="$LOADERS_DIR/emmu_loader.py"
echo "Installing link $NEW_LOADER -> $ORIG_LOADER"
ln -s $ORIG_LOADER $NEW_LOADER

ORIG_DIR="$DIR/loader/emmu_loader"
NEW_DIR="$PYTHON_DIR/emmu_loader"
echo "Installing link $NEW_DIR -> $ORIG_DIR"
ln -s $ORIG_DIR $NEW_DIR
#!/bin/sh
BUILD_DIR="./builddir/go"
echo "[*] Running IDA with coverage script"
EMMU="$BUILD_DIR/emmu"
ROM="../SecureROMs-master/SecureROM for t8030si, iBoot-4479.0.0.100.4"
COV_DIR="$PWD/../results/coverage/aggr"
OUT_DIR="$PWD/../writing/coverage"
export LIGHTHOUSE_LOGGING=yes
$EMMU ida script -t -a -i "$ROM" "$PWD/python/scripts/coverage.py" "$COV_DIR" "$OUT_DIR"
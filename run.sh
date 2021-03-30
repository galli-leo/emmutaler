#!/bin/bash
echo "Doing fuzzing"

BINARY=./emmu_fuzz
HOOK=../pers_hook/hook.so
#HOOK=./libhook.so
IN=../img
AFL="../../AFLplusplus"
AFL_FUZZ="$AFL/afl-fuzz"
CMP_LIB="$AFL/libcmpcov.so"
DICT=./img4.dict
export QEMU_LD_PREFIX=/usr/aarch64-linux-gnu

echo "Fuzzing $BINARY with hook $HOOK and inputs $IN"

PERS_ADDR=0x$(nm $BINARY | grep "T do_fuzz" | awk '{print $1}')

echo "PERSISTENT ADDRESS: $PERS_ADDR"

# export AFL_QEMU_SNAPSHOT=$PERS_ADDR
# export AFL_QEMU_PERSISTENT_HOOK=$HOOK
#export AFL_QEMU_PERSISTENT_RET=0x4012cc

echo "Persistent Addr is at 0x$AFL_QEMU_PERSISTENT_ADDR"

CACHE_SIZE=1000

CMD="AFL_QEMU_SNAPSHOT=$PERS_ADDR AFL_TESTCACHE_SIZE=$CACHE_SIZE AFL_QEMU_PERSISTENT_HOOK=$HOOK $AFL_FUZZ -Q -x $DICT -i - -o out2"

echo "$CMD"

tmux start-server

tmux new-session -d -s fuzzing -c $PWD "$CMD -M fuzzer0 -- $BINARY"

# bash -c "$CMD -- $BINARY"

tmux new-window -t fuzzing:1 -c $PWD "AFL_COMPCOV_LEVEL=2 $CMD -c 0 -S fuzzer1 -- $BINARY"
tmux new-window -t fuzzing:2 -c $PWD "AFL_USE_QASAN=1 $CMD -S fuzzer2 -- $BINARY; bash -i"
tmux new-window -t fuzzing:3 -c $PWD "AFL_COMPCOV_LEVEL=2 AFL_PRELOAD=$CMP_LIB $CMD -S fuzzer3 -- $BINARY; bash -i"

for i in {4..15}
do
    NAME="fuzzer$i"
    echo "Launching $NAME"
    # tmux split-window -t fuzzing:0 -c $PWD "$CMD -S $NAME -- $BINARY"
    tmux new-window -t fuzzing:$i -c $PWD "$CMD -S $NAME -- $BINARY; bash -i"
    # tmux select-layout -t fuzzing:0 tiled
done

# tmux select-layout -t fuzzing:0 tiled

tmux attach -t fuzzing
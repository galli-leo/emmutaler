#!/bin/bash
echo "Doing fuzzing"

OOB=""
SMALL=""

while : ; do
  case "$1" in 
    small)
       [ -n "${VMMOUNT}" ] && usage
       SMALL="_small"
       shift 1 ;;
    oob)
       [ -n "${BOOTSTRAP}" ] && usage
       OOB="_oob"
       shift 1 ;;
    *)
       break ;;
  esac
done

BINARY="./emmu_usb_fuzz"
HOOK=./hook.so
#HOOK=./libhook.so
IN=./usb_msg
AFL="../afl"
AFL_FUZZ="$AFL/bin/afl-fuzz"
CMP_LIB="$AFL/lib/libcmpcov.so"
DICT=./img4.dict
export QEMU_LD_PREFIX=/usr/aarch64-linux-gnu

echo "Fuzzing $BINARY with hook $HOOK and inputs $IN"

PERS_ADDR=0x$(nm $BINARY | grep "T do_fuzz" | awk '{print $1}')

echo "PERSISTENT ADDRESS: $PERS_ADDR"

# export AFL_QEMU_SNAPSHOT=$PERS_ADDR
# export AFL_QEMU_PERSISTENT_HOOK=$HOOK
#export AFL_QEMU_PERSISTENT_RET=0x4012cc
INST_RANGES="0xfffff000-0x100029000,0x401000-0x405000"
# DATA_RANGES="00000003200597d0-0x00000003200997d0,0x0000005500000000-0x000000550086a99c,0x19c000000-0x19c064000"

echo "Persistent Addr is at 0x$PERS_ADDR"

CACHE_SIZE=1000

CMD="AFL_QEMU_DEBUG_MAPS=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_QEMU_PERSISTENT_CNT=100 AFL_QEMU_DATA_RANGES=$DATA_RANGES AFL_QEMU_INST_RANGES=$INST_RANGES QEMU_LD_PREFIX=/usr/aarch64-linux-gnu AFL_QEMU_SNAPSHOT=$PERS_ADDR AFL_TESTCACHE_SIZE=$CACHE_SIZE AFL_QEMU_PERSISTENT_HOOK=$HOOK AFL_QEMU_PERSISTENT_MEM=0 $AFL_FUZZ -Q -t 5000 -x $DICT -i $IN -o out$SMALL$OOB"

echo "AFL_DEBUG_CHILD=1 $CMD -- $BINARY"

# bash -c "AFL_DEBUG_CHILD=1 $CMD -- $BINARY"
# exit 0

# tmux start-server

# kill existing session
# tmux kill-session -t fuzzing

# bash -c "AFL_DEBUG_CHILD=1 $CMD -M fuzzer0 -- $BINARY"
# exit 0

tmux new-session -d -s fuzzing -c $PWD "AFL_DEBUG_CHILD=1 $CMD -M fuzzer0 -- $BINARY; bash -i"

# bash -c "$CMD -- $BINARY"

tmux new-window -t fuzzing:1 -c $PWD "AFL_COMPCOV_LEVEL=2 $CMD -c 0 -S fuzzer1 -- $BINARY; bash -i"
tmux new-window -t fuzzing:2 -c $PWD "AFL_USE_QASAN=1 $CMD -S fuzzer2 -- $BINARY; bash -i"
tmux new-window -t fuzzing:3 -c $PWD "AFL_COMPCOV_LEVEL=2 AFL_PRELOAD=$CMP_LIB $CMD -S fuzzer3 -- $BINARY; bash -i"
tmux new-window -t fuzzing:4 -c $PWD "$CMD -c 0 -l AT -S fuzzer4 -- $BINARY"

# tmux select-pane -t fuzzing:0
# tmux attach -t fuzzing:0
# exit 0
for i in {5..11}
do
    NAME="fuzzer$i"
    echo "Launching $NAME"
    # tmux split-window -t fuzzing:0 -c $PWD "$CMD -S $NAME -- $BINARY"
    tmux new-window -t fuzzing:$i -c $PWD "$CMD -S $NAME -- $BINARY; bash -i"
    # tmux select-layout -t fuzzing:0 tiled
done

# tmux select-layout -t fuzzing:0 tiled
tmux select-pane -t fuzzing:0
tmux attach -t fuzzing
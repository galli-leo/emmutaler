#!/bin/bash
NODE_NAME="ee-tik-cn00"
OUT_DIR="/data/gallile/results/queue"
for i in {1..4}
do
    echo "Copying queue for node $i"
    node="$NODE_NAME$i"
    jobid=$(squeue -h -w $node | awk '{print $1}')
    # echo "Jobid: $jobid"
    srun --jobid $jobid /bin/bash -c "cd fuzzing && cp out*/fuzzer*/queue/* $OUT_DIR"
    # for j in {0,1,3,4}
    # do
    #     fuzzer_name="fuzzer$j"
    #     # echo "Fuzzer stats $fuzzer_name"
    #     srun --jobid $jobid /bin/bash -c "cd fuzzing && cp out*/$fuzzer_name/fuzzer_stats | grep -i bitmap_cvg"
    # done

    echo "--------------------------------------"
    echo ""
done
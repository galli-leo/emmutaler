#!/bin/bash
NODE_NAME="ee-tik-cn00"
for i in {7..9}
do
    echo "Listing stats for node $i"
    node="$NODE_NAME$i"
    jobid=$(squeue -h -w $node | awk '{print $1}')
    # echo "Jobid: $jobid"
    srun --jobid $jobid /bin/bash -c "cd fuzzing && ../afl/bin/afl-whatsup -s out*"
    for j in {0,1,3,4}
    do
        fuzzer_name="fuzzer$j"
        echo "Fuzzer stats $fuzzer_name"
        srun --jobid $jobid /bin/bash -c "cd fuzzing && cat out*/$fuzzer_name/fuzzer_stats | grep -i bitmap_cvg"
    done

    echo "--------------------------------------"
    echo ""
done
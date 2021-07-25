import os
import sys
import re
import subprocess
from progressbar import progressbar, ProgressBar
import glob
import tempfile
import shutil
import argparse
from concurrent.futures.thread import ThreadPoolExecutor

def auto_int(x):
    return int(x, 0)

parser = argparse.ArgumentParser(description="Convert a fuzzing directory into detailed coverage information.")
parser.add_argument("input", type=str, help="Input fuzzing directory. Should be output directory specified to AFL++")
parser.add_argument("binary", type=str, help="Path to binary used for generating coverage files.")
parser.add_argument("output", type=str, help="Output coverage directory.")

INSTR_START = 0x0000000100000000
INSTR_END = INSTR_START + 0x25390

parser.add_argument("--threads", "-t", type=int, default=1, help="Number of threads to run concurrently.")
parser.add_argument("--start", "-s", type=auto_int, default=INSTR_START, help="Instruction start, from where to gather coverage from.")
parser.add_argument("--end", "-e", type=auto_int, default=INSTR_END, help="Instruction end, until when to gather coverage from.")
parser.add_argument("--timeout", type=float, default=5, help="Timeout for execution.")

args = parser.parse_args()

inp = args.input
bin = args.binary
out = args.output
print(f"[*] running {bin} with fuzzing dir: {inp}")

def collect_coverage(item):
    fuzzer, file, filepath = item
    fd, temp_out = tempfile.mkstemp(suffix=".cov")
    os.close(fd)
    cmd = ["../../qemu-user-static/bin/qemu-aarch64", "-plugin", f"../../qemu/contrib/plugins/libcvg.so,arg=start=0x100000000,arg=end=0x100025390,arg=out={temp_out},arg=inline", bin, filepath]
    # print(" ".join(cmd))
    try:
        subprocess.run(cmd, shell=False, env=os.environ, timeout=args.timeout)
    except Exception:
        pass
    out_path = os.path.join(out, fuzzer, f"{file}.cov")
    shutil.move(temp_out, out_path)
    try:
        stinfo = os.stat(filepath)
        os.utime(out_path, (stinfo.st_atime, stinfo.st_mtime))
    except Exception:
        print(f"[!] Could not resolve times for file {filepath}, cannot change output times!")

files = os.listdir(inp)
idx = 0
total_files = []
for fuzzer in files:
    fuzzer_queue = os.path.join(inp, fuzzer, "queue")
    queue_files = os.listdir(fuzzer_queue)
    fuzzer_out = os.path.join(out, fuzzer)
    try:
        os.makedirs(fuzzer_out)
    except:
        pass
    for file in queue_files:
        if ".state" in file:
            continue
        filepath = os.path.join(fuzzer_queue, file)
        total_files.append((fuzzer, file, filepath))

with ThreadPoolExecutor(max_workers=args.threads) as executor:
    bar = ProgressBar(maxval=len(total_files))
    bar.start()
    thread_iter = executor.map(collect_coverage, total_files)
    idx = 1
    for _ in thread_iter:
        bar.update(idx)
        idx += 1
    bar.finish()
        

    

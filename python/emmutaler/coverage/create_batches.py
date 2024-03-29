from emmutaler.log import get_logger
import lighthouse
from lighthouse.context import LighthouseContext
import os
import glob

log = get_logger(__name__)

SPECIAL_FUZZERS = {
    "fuzzer0": "main",
    "fuzzer1": "comp_cov",
    "fuzzer2": "comp_cov_lib",
    "fuzzer3": "qasan",
    "fuzzer4": "cmp_log"
}

def load_coverage_batch(pattern, name):
    """Loads coverage files found by pattern with glob.

    Parameters
    ----------
    pattern : [type]
        glob pattern describing where to find coverage files.
        For example: /home/users/me/results/fuzzer*/*.cov
    name : [type]
        The name of the batch that will be created.
    """
    filenames = glob.glob(pattern)
    log.info("Loading %d files for batch %s", len(filenames), name)
    ctx: LighthouseContext = lighthouse.get_context(None)
    ctx.director.load_coverage_batch(filenames, name, progress_callback=log.info)
    return len(filenames)
    

def load_fuzzing_cov(path, name):
    """Loads the coverage generated by a fuzzing queue.
    Coverage generated by some fuzzers are loaded with special batch names (such as CompLog).
    Finally, there is a batch for all coverage combined. This means we load coverage multiple times, but whatever.

    Parameters
    ----------
    path : [type]
        Path to folder containing fuzzer*/*.cov
    name : [type]
        Name to prepend to all batches
    """
    log.info("Loading coverage for %s with path %s", name, path)
    names = []
    for folder in os.listdir(path):
        full_folder = os.path.join(path, folder)
        if folder in SPECIAL_FUZZERS:
            folder_name = SPECIAL_FUZZERS[folder]
            log.info("Found special cased %s: %s", folder, folder_name)
            pattern = os.path.join(full_folder, "*.cov")
            batch_name = f"{name}_{folder_name}"
            num_files = load_coverage_batch(pattern, batch_name)
            names.append((batch_name, num_files))
    add_names = load_fuzzing_cov_full(path, name)
    names += add_names
    return names

def load_fuzzing_cov_full(path, name):
    # finally, load full coverage
    full_name = f"{name}_all"
    num_files = load_coverage_batch(os.path.join(path, "*", "*.cov"), full_name)
    return [(full_name, num_files)]

def load_aggr_cov(path, name):
    log.info("Loading coverage for %s with path %s", name, path)
    names = []
    ctx: LighthouseContext = lighthouse.get_context(None)
    for aggr in os.listdir(path):
        aggr_name, ext = os.path.splitext(aggr)
        filepath = os.path.join(path, aggr)
        batch_name = f"{name}_{aggr_name}"
        names.append((batch_name, 1))
        ctx.director.load_coverage_batch([filepath], batch_name)
    return names
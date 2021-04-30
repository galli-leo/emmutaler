import logging
import coloredlogs
import argparse
from emmutaler.util import get_plugin_args
import sys

parser = argparse.ArgumentParser(description="log file arguments")
parser.add_argument("--log-file", default="")
args, _ = parser.parse_known_args(get_plugin_args())
log_file = sys.stderr
if args.log_file != "":
    log_file = open(args.log_file, "w")

def get_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.handlers = []
    # logger.addHandler(ch)
    coloredlogs.install(level='INFO', logger=logger, isatty=True, stream=log_file)
    return logger
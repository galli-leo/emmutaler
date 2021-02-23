import logging
logger = logging.getLogger("emmu_loader")
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter('[%(name)-12s] %(levelname)-8s %(message)s')
ch.setFormatter(formatter)
logger.setLevel(logging.INFO)
for handler in logger.handlers:
    logger.removeHandler(handler)
logger.addHandler(ch)
log = logger
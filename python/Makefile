PROTOS := $(wildcard ../proto/*.fbs)

.PHONY: flatc
flatc: $(PROTOS)
	flatc --gen-mutable --gen-object-api --python $(PROTOS)

LOADER := $(abspath scripts/emmu_loader.py)
PACKAGE := $(abspath emmutaler)
IDA_PATH ?= $(HOME)/.idapro/
LOADER_PATH := $(IDA_PATH)/loaders/emmu_loader.py
PYTHON_PATH := $(IDA_PATH)/python/emmutaler

.PHONY: install
install:
	rm $(LOADER_PATH) || true
	ln -s $(LOADER) $(LOADER_PATH)
	rm $(PYTHON_PATH) || true
	ln -s $(PACKAGE) $(PYTHON_PATH)

TEST_IMAGE := ../../SecureROMs-master/SecureROM\ for\ t8030si,\ iBoot-4479.0.0.100.4

.PHONY: test-loader
test-loader:
	../bin/emmu ida $(TEST_IMAGE)

TEST_SCRIPT := $(abspath scripts/symbolicate.py)

.PHONY: test-symbolicate
test-symbolicate:
	../bin/emmu ida --gui=false -s $(TEST_SCRIPT) $(TEST_IMAGE)


PATCH_AMIE := scripts/patch_amie.py
.PHONY: patch_amie
patch_amie: $(PATCH_AMIE)
	IDA_PATH=$(IDA_PATH) python3 $(PATCH_AMIE)
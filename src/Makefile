null      :=
SPACE     := $(null) $(null)
ROM := rom
TEXT_SIZE := 152464
ARCH := aarch64-unknown-linux-gnu
OBJCOPY=$(ARCH)-objcopy
CC=/Volumes/cross-build/aarch64/bin/$(ARCH)-gcc
AS=/Volumes/cross-build/aarch64/bin/$(ARCH)-as
CC_FLAGS=-I /Volumes/cross-build/aarch64/bin/include -g3 -ggdb
LD_FLAGS=-L/Volumes/cross-build/aarch64/lib

build:
	mkdir build

build/rom.text: build
	dd if=$(ROM) bs=$(TEXT_SIZE) count=1 > build/rom.text

build/rom.data: build
	dd if=$(ROM) bs=$(TEXT_SIZE) skip=1 > build/rom.data

build/rom.o: rom.S Makefile
	$(AS) -o build/rom.o $(CC_FLAGS) rom.S

.PHONY: split-file
split-files: build/rom.text build/rom.data

debug/signals.o: debug/signals.c debug/signals.h debug/signals_list.h Makefile
	cd debug && $(CC) -c -g -o signals.o -I $(PWD) $(CC_FLAGS) signals.c

debug/stacktrace.o: debug/stacktrace.c debug/stacktrace.h debug/register-dump.h Makefile
	cd debug && $(CC) -c -g -o stacktrace.o -I $(PWD) $(CC_FLAGS) stacktrace.c

main: build/rom.o main.c hexdump.c debug/signals.o debug/stacktrace.o
	$(CC) $(LD_FLAGS) -march=armv8.3-a -Wl,--section-start=.rom.text=0xffffffe8 -Wl,--section-start=.rom.heap=0x19C028000 -Wl,--section-start=.rom.data=0x19c00c000 -Wl,--section-start=.rom.io=0x23D2B8000 -Wl,--section-start=.rom.pmgr=0x23B0B8000 -Wl,--section-start=.rom.gpio=0x23c100000 -Wl,--section-start=.rom.pt=0x19c000000 -Wl,--section-start=.rom.stack=0x19c01c000 -Wl,--section-start=.rom.bss=0x19c00d100 -Wl,-Map,output.map -o main -I $(PWD) -static -fno-pie -no-pie -fno-omit-frame-pointer -g main.c build/rom.o hexdump.c debug/signals.o debug/stacktrace.o bug.S

bug: bug.c Makefile
	$(CC) -march=armv8.3-a -o bug -I $(PWD) -static -fno-pie -no-pie -fno-omit-frame-pointer -g bug.c bug.S

run-bug: bug
	./bug
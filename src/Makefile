null      :=
SPACE     := $(null) $(null)
ROM := rom
TEXT_SIZE := 152464
ARCH := aarch64-linux-gnu
OBJCOPY=$(ARCH)-objcopy
CC=$(ARCH)-gcc
AS=$(ARCH)-as
CC_FLAGS=-I /usr/include/aarch64-linux-gnu/

build:
	mkdir build

build/rom.text: build
	dd if=$(ROM) bs=$(TEXT_SIZE) count=1 > build/rom.text

build/rom.data: build
	dd if=$(ROM) bs=$(TEXT_SIZE) skip=1 > build/rom.data

build/rom.o: build/rom.data build/rom.text
	$(AS) -o build/rom.o rom.S

.PHONY: split-file
split-files: build/rom.text build/rom.data

debug/signals.o: debug/signals.c debug/signals.h debug/signals_list.h
	cd debug && $(CC) -c -g -o signals.o -I $(PWD) $(CC_FLAGS) signals.c

debug/stacktrace.o: debug/stacktrace.c debug/stacktrace.h
	cd debug && $(CC) -c -g -o stacktrace.o -I $(PWD) $(CC_FLAGS) stacktrace.c

main: build/rom.o main.c hexdump.c debug/signals.o debug/stacktrace.o
	$(CC) -Wl,--section-start=.rom.text=0xffffffe8 -Wl,--section-start=.rom.data=0x19c00c000 -Wl,-Map,output.map -o main -I $(PWD) -static -fno-pie -no-pie -fno-omit-frame-pointer -g main.c build/rom.o hexdump.c debug/signals.o debug/stacktrace.o -lbacktrace
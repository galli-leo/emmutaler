# emmutaler

A set of tools to enable fuzzing of the iPhone boot loader (and much more).
This was developed for my thesis.
For some more information of how certain parts of this work, see [my thesis](docs/thesis.pdf).

I plan on sharing my `*.idb` for the different SecureROMs sometime soon.
Need to first figure out whats the best way to do that :)

I also need to figure out a License for this (not sure if I am using anything that requires me to have a restrictive license).
If you need to use it urgently and are concerned about the license, let me know :)

# Directory Layout

The following is very incomplete, but it should give you an idea on what to look for where.

## go/

Contains the go part of this project.
The go part contains the binary patcher, IMG4 generation and other things such as generating various files for the compilation of the final binary.

It also contains commands to make it easier to run IDA from build scripts.

## python/

Contains the python part of this project.
Almost all python things are used inside IDA.

### python/scripts/

Contains various scripts that are ran inside IDA.

- `coverage.py`: Loads coverage into lighthouse, then creates tikz graphs and latex tables. Beware this is ugly
- `emmu_loader.py`: A SecureROM loader for IDA that works more nicely than what I could find before. Requires the go part of this project however to be ran against the SecureROM beforehand.
- `symbolicate.py`: Exports symbols from IDA into a format that the go part can understand. We can then use these symbols from our C code.

### python/emmutaler/

The python package contain a lot of code used by the scripts.

## src/

Contains the C code that builds to the main binary that will be fuzzed.
Lots of sorcery going on here :)

### src/heap/

Contains the custom heap implementation, FETA.

### src/usb/

Contains a bunch of the USB stuff used for fuzzing USB messages.
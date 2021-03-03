/*
Here we have all code responsible for building a usable ROM image.
This consists of:
- patching the ROM image with a patcher script.
- building the IO memory section(s).
- writing out the assembly file for a given ROM image.
- assembling the ROM image.
- writing a configuration file with the correct linker flags.
*/
package rom

project('emmutaler', 'c', version: '0.1', default_options: ['default_library=static'])

# Configure path to rom
ROMS = {
    't8030': 'SecureROM for t8030si, iBoot-4479.0.0.100.4'
}
rom_path = get_option('rom_path')
rom_id = get_option('rom')
rom_filename = ROMS[rom_id]
rom_filepath = join_paths(rom_path, rom_filename)
rom = files(rom_filepath)
rom_dep = files(
    rom_filepath + '.i64',
    rom_filepath + '.emmu',
    rom_filepath,
)

summary({
    'rom': rom_filepath
}, section: 'ROM')

test_file = join_paths('ipsw', 'out.img4')
custom_test = join_paths('img', 'test.img4')
summary({
    'test_file': test_file,
    'custom_test': custom_test
}, section: 'testing')

# TODO: Make this generateable??
SECTIONS = {
    'text': '0xffffffe8',
    'heap': '0x19C028000',
    'data': '0x19c00c000',
    'io': '0x23D2B8000',
    'pmgr': '0x23B0B8000',
    'gpio': '0x23c100000',
    'pt': '0x19c000000',
    'stack': '0x19c01c000',
    'bss': '0x19c00d100',
    'fuses': '0x23D2BC000',
    'aes': '0x23d2d0000',
    'img': '0x420069000'
}

summary(SECTIONS, section: 'memory_map')

mmap_flags = []
foreach name, val : SECTIONS
    mmap_flags += ['-Wl,--section-start=.rom.@0@=@1@'.format(name, val)]
endforeach
summary({
    'mmap_flags': mmap_flags
}, section: 'memory_map')

# Get flatbuffers
subdir('proto')
flatc = find_program('flatc')

# Go
subdir('go')

# Python
subdir('python')

# Actual code
subdir('src')
project('emmutaler', 'c', version: '0.1')

# Configure path to rom
ROMS = {
    't8030': 'SecureROM for t8030si, iBoot-4479.0.0.100.4'
}
rom_path = get_option('rom_path')
rom_id = get_option('rom')
rom_filename = ROMS[rom_id]
rom_filepath = join_paths(rom_path, rom_filename)
rom = files(rom_filepath)

summary({
    'rom': rom_filepath
}, section: 'ROM')

# Get flatbuffers
subdir('proto')
flatc = find_program('flatc')

# Go
subdir('go')

# Python
subdir('python')
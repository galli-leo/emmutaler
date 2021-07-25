project('emmutaler', 'c', version: '0.1', default_options: ['default_library=static'])

# Configure path to rom
ROMS = {
    't8030': 'SecureROM for t8030si, iBoot-4479.0.0.100.4',
    't8101': 'SecureROM for t8101si, iBoot-5281.0.0.100.22'
}
rom_path = get_option('rom_path')
rom_id = get_option('rom')
rom_filename = ROMS[rom_id]
rom_filepath = join_paths(meson.current_source_dir(), rom_path, rom_filename)
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
img_gen_test = join_paths('img', 'img_0002.img4')
img_gen_path = join_paths('img')
summary({
    'test_file': test_file,
    'custom_test': custom_test,
    'img_gen_test': img_gen_test,
    'img_gen_path': img_gen_path
}, section: 'testing')

# TODO: Make this generateable??
ROM_SECTIONS = {
    't8030': {
        'heap': '0x19C028000',
        'data': '0x19c00c000',
        'pt': '0x19c000000',
        'stack': '0x19c01c000',
        'bss': '0x19c00d100',
        'pmgr': '0x23B0B8000',
    },
    't8101': {
        'heap': '0x1FC040000',
        'data': '0x1fc00c000',
        'pt': '0x1fc000000',
        'stack': '0x1fc030000',
        'bss': '0x1fc020000',
        'pmgr': '0x23B738000',
    }
}

# TODO: Make this generateable??
SECTIONS = {
    'text': '0xffffffe8',
    'io': '0x23D2B8000',
    'gpio': '0x23c100000',
    'fuses': '0x23D2BC000',
    'aes': '0x23d2d0000',
    'img': '0x320069000',
    'allow': '0x2000000'
}

SECTIONS += ROM_SECTIONS[rom_id]

summary(SECTIONS, section: 'memory_map')

mmap_flags = []
foreach name, val : SECTIONS
    mmap_flags += ['-Wl,--section-start=.rom.@0@=@1@'.format(name, val)]
endforeach
summary({
    'mmap_flags': mmap_flags
}, section: 'memory_map')

fuzz_host = get_option('fuzz_host')
fuzz_user = get_option('fuzz_user')
fuzz_dir = get_option('fuzz_dir')

summary({
    'fuzz_host': fuzz_host,
    'fuzz_user': fuzz_user,
    'fuzz_dir': fuzz_dir
}, section: 'fuzz')

# Get flatbuffers
subdir('proto')
flatc = find_program('flatc')

# Go
subdir('go')

# Python
subdir('python')

# Actual code
subdir('src')

fuzz_scp_prog = find_program('fuzz_scp.sh')

fuzz_scp = custom_target(
    'fuzz_scp',
    input: ['./fuzz_scp.sh', '../img', 'run.sh', emmu_fuzz, main, repro_fuzz, emmu_usb_fuzz] + emmu_fuzz_extras,
    output: 'fuzz_scp',
    command : [fuzz_scp_prog, fuzz_host, fuzz_user, fuzz_dir, '@INPUT@']
)

if add_languages('cpp', required : true)
    cov_aggr = executable('cov_aggr', 'cov_aggr.cpp', native: true, override_options: ['cpp_std=c++17'], cpp_args: ['-O3'])
endif
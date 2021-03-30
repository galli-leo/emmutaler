inc = include_directories('.')

rom_cmd += ['--out', meson.current_build_dir()]

rom_inps = rom_dep + [types_h]

rom_s = custom_target(
    'rom_s',
    input: rom_inps,
    output: 'rom.S',
    command : rom_cmd + ['asm']
)

rom_h = custom_target(
    'rom_h',
    input: rom_inps,
    output: 'rom.h',
    command : rom_cmd + ['header']
)

symbols_list_h = custom_target(
    'symbols_list_h',
    input: rom_inps,
    output: 'symbols_list.h',
    command : rom_cmd + ['symh']
)

run_target(
    'edit_rom',
    command : ida_cmd + ['--gui=true', '--log', '--temp=false']
)


subdir('debug')

common_src = files(
    'rom/rom_extra.h',
    'handlers/arch.c',
    'handlers/reports.c',
    'handlers/panic.c',
    'hexdump.h',
    'hexdump.c'
)
common_src += debug_src
common_src += rom_s
common_src += rom_h
common_src += types_h

std_flags = ['-static', '-g', '-fno-pie', '-no-pie', '-fno-omit-frame-pointer', '-march=armv8.3-a']

std_link_flags = mmap_flags # + ['-static'] static is actually only for libraries we want to fuzz.

summary({
    'std_gcc_flags': std_flags,
    'std_link_flags': std_link_flags,
}, section: 'gcc')

subdir('tests')

src = files(
    'main.c',
    #'rom.h' # TODO: Make generated rom.h actually includable!
)
src += common_src



main = executable('main', src, include_directories: inc, link_args: std_link_flags, c_args: std_flags + ['-DDEBUG=1'])
test('main_test', main, args : [test_file], is_parallel: false)
test('main_custom_test', main, args : [custom_test], is_parallel: false)

emmu_fuzz = executable('emmu_fuzz', ['main_fuzz.c'] + common_src, include_directories: inc, link_args: std_link_flags, c_args: std_flags)
test('emmu_fuzz_test', emmu_fuzz, args : [custom_test], is_parallel: false)

subdir('persistent_hook')
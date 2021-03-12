inc = include_directories('.')

rom_cmd += ['--out', meson.current_build_dir()]

rom_s = custom_target(
    'rom_s',
    output: 'rom.S',
    command : rom_cmd + ['asm']
)

rom_h = custom_target(
    'rom_h',
    output: 'rom.h',
    command : rom_cmd + ['header']
)

symbols_list_h = custom_target(
    'symbols_list_h',
    output: 'symbols_list.h',
    command : rom_cmd + ['symh']
)


subdir('debug')


src = files(
    'main.c',
    'rom.h' # TODO: Make generated rom.h actually includable!
)
src += debug_src
src += rom_s
# src += rom_h

std_flags = ['-static', '-g', '-fno-pie', '-no-pie', '-fno-omit-frame-pointer', '-march=armv8.3-a']

summary({
    'std_gcc_flags': std_flags
}, section: 'gcc')

main = executable('main', src, include_directories: inc, link_args: mmap_flags, c_args: std_flags)
test('main_test', main, args : [test_file])
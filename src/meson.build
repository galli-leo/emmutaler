inc = include_directories('.')

rom_cmd += ['--out', '@OUTDIR@']

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
subdir('config')

common_src = files(
    'rom/rom_extra.h',
    'handlers/arch.c',
    'handlers/reports.c',
    'handlers/panic.c',
    'hexdump.h',
    'hexdump.c'
)
common_src += debug_src
common_src += types_h
common_src += config_src

rom_gen_src = [rom_h, rom_s, symbols_list_h]


std_flags = ['-g', '-fno-pie', '-no-pie', '-fno-omit-frame-pointer', '-march=armv8.3-a']

std_link_flags = mmap_flags # + ['-static'] static is actually only for libraries we want to fuzz.

summary({
    'std_gcc_flags': std_flags,
    'std_link_flags': std_link_flags,
}, section: 'gcc')

subdir('tests')

src = files(
    'main.c',
)
src += common_src



main = executable('main', src + rom_gen_src, include_directories: inc, link_args: std_link_flags, c_args: std_flags + ['-DDEBUG=1'])
test('main_test', main, args : [test_file], is_parallel: false)
test('main_custom_test', main, args : [custom_test], is_parallel: false)

gen_imgs = [0, 1, 2]
foreach num : gen_imgs
    filename = 'img_000@0@.img4'.format(num)
    test('main_img_gen_test_'+filename, main, args : [join_paths(img_gen_path, filename)], is_parallel: false, suite: 'main_img_gen_test')
endforeach
# test('main_img_gen_test', main, args : [img_gen_test], is_parallel: false)
test('main_run', main, is_parallel: false)

fuzz_src = files(
    'main_fuzz.c'
)

emmu_fuzz_src = fuzz_src + common_src

emmu_fuzz = executable('emmu_fuzz', emmu_fuzz_src + rom_gen_src, include_directories: inc, link_args: std_link_flags, c_args: std_flags)
test('emmu_fuzz_test', emmu_fuzz, args : [custom_test], is_parallel: false)

subdir('extras')

repro_src = files(
    'repro_fuzz.c'
)
repro_fuzz = executable('repro_fuzz', repro_src, include_directories: inc, link_args: std_link_flags, c_args: std_flags)

subdir('persistent_hook')
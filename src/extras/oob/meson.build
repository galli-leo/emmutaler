rom_s_config = custom_target(
    'rom_s_'+name,
    input: rom_inps,
    output: 'rom.S',
    command : config_rom_cmd + ['asm']
)

rom_h_config = custom_target(
    'rom_h_'+name,
    input: rom_inps,
    output: 'rom.h',
    command : config_rom_cmd + ['header']
)

symbols_list_h_config = custom_target(
    'symbols_list_h_'+name,
    input: rom_inps,
    output: 'symbols_list.h',
    command : config_rom_cmd + ['symh']
)

rom_gen_src_config = [rom_s_config, rom_h_config, symbols_list_h_config]
emmu_fuzz_oob = executable('emmu_fuzz_'+name, emmu_fuzz_src + rom_gen_src_config, include_directories: inc, link_args: std_link_flags, c_args: std_flags + build_args)
main_oob = executable('main_'+name, src + rom_gen_src_config, include_directories: inc, link_args: std_link_flags, c_args: std_flags + ['-DDEBUG=1'] + build_args)
test('main_'+name+'_run', main_oob, is_parallel: false)

emmu_fuzz_extras += emmu_fuzz_oob
emmu_fuzz_extras += main_oob
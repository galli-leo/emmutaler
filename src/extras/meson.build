configs = {
    'oob': [
        ['--allow-oob'], # rom args
        ['-DALLOW_OOB=1'] # build args
    ]
}

emmu_fuzz_extras = []

foreach name, args : configs
    rom_args = args[0]
    build_args = args[1]

    config_rom_cmd = rom_cmd + rom_args

    subdir(name)

endforeach
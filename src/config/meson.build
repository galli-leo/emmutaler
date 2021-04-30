config_h = custom_target(
    'config_h',
    input: rom_inps,
    output: 'config.h',
    command : rom_cmd + ['configh']
)

config_src = files(
    'version.h'
)
config_src += config_h
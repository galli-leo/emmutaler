module github.com/galli-leo/emmutaler

go 1.16

require (
	github.com/Workiva/go-datastructures v1.0.52
	github.com/fsnotify/fsnotify v1.4.9
	github.com/google/flatbuffers v1.12.0
	github.com/google/gofuzz v1.2.0
	github.com/magiconair/properties v1.8.4 // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/pelletier/go-toml v1.8.1 // indirect
	github.com/spf13/afero v1.5.1 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v1.1.3
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.4.0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1
	golang.org/x/arch v0.0.0-20210315020452-ea130f1b0a00
	golang.org/x/crypto v0.0.0-20210317152858-513c2a44f670 // indirect
	golang.org/x/sys v0.0.0-20210317091845-390168757d9c // indirect
	golang.org/x/text v0.3.5 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
	gopkg.in/ini.v1 v1.62.0 // indirect
)

replace golang.org/x/arch => ../../arch

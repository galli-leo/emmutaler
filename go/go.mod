module github.com/galli-leo/emmutaler

go 1.16

require (
	github.com/Workiva/go-datastructures v1.0.52
	github.com/fsnotify/fsnotify v1.4.7 // indirect
	github.com/google/flatbuffers v1.12.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/spf13/cobra v1.1.3
	github.com/spf13/viper v1.7.1
	golang.org/x/arch v0.0.0-20210222215009-a3652b17bebe
	golang.org/x/xerrors v0.0.0-20190717185122-a985d3407aa7
)

replace golang.org/x/arch => ../../arch
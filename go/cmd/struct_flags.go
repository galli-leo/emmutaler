package cmd

import (
	"reflect"

	"github.com/iancoleman/strcase"
	"github.com/spf13/pflag"
	"golang.org/x/xerrors"
)

func AddStructFlags(flags *pflag.FlagSet, struc interface{}) error {
	v := reflect.ValueOf(struc)
	if v.Kind() != reflect.Ptr {
		return xerrors.Errorf("expected ptr type not %s", v.Kind())
	}
	v = v.Elem()
	numFields := v.NumField()
	t := v.Type()
	for i := 0; i < numFields; i++ {
		field := v.Field(i)
		fieldT := t.Field(i)
		fieldPtr := field.Addr()
		fvi := field.Interface()
		fvpi := fieldPtr.Interface()
		name := fieldT.Name
		name = strcase.ToKebab(name)
		if tname, ok := fieldT.Tag.Lookup("name"); ok {
			name = tname
		}
		short := ""
		if tshort, ok := fieldT.Tag.Lookup("short"); ok {
			short = tshort
		}
		help := ""
		if thelp, ok := fieldT.Tag.Lookup("help"); ok {
			help = thelp
		}
		switch field.Kind() {
		case reflect.Bool:
			flags.BoolVarP(fvpi.(*bool), name, short, fvi.(bool), help)
		}
	}
	return nil
}

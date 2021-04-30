package mutation

import (
	"fmt"
	"math/rand"
	"reflect"
	"regexp"

	fuzz "github.com/google/gofuzz"
)

func NewStruct(times int, accessor interface{}) *StructMutator {
	return &StructMutator{
		Times:    times,
		Accessor: reflect.ValueOf(accessor),
	}
}

type StructMutator struct {
	Times    int
	Accessor reflect.Value
}

func (s *StructMutator) Mutate(target reflect.Value, comb int) (name string) {
	if comb == 0 {
		return
	}
	if s.Accessor.Kind() == reflect.Func && !s.Accessor.IsNil() {
		target = s.Accessor.Call([]reflect.Value{target})[0]
	}
	target = target.Elem()
	nf := target.NumField()
	fn := rand.Intn(nf)
	rf := target.Field(fn)
	tn := target.Type().Name()
	fieldName := target.Type().Field(fn).Name
	fuzzer := fuzz.New().SkipFieldsWithPattern(regexp.MustCompile("CertChain|Value|PublicKey|Digest"))
	if rf.Addr().CanInterface() {
		fuzzer.Fuzz(rf.Addr().Interface())
	}
	if rf.CanInterface() {
		name = fmt.Sprintf(`%s.%s=%v`, tn, fieldName, rf.Interface())
	} else {
		name = fmt.Sprintf(`%s.%s`, tn, fieldName)
	}
	return
}

func (s *StructMutator) Combinations() int {
	return s.Times + 1
}

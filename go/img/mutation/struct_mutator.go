package mutation

import (
	"fmt"
	"math/rand"
	"reflect"

	fuzz "github.com/google/gofuzz"
)

type StructMutator struct {
	Times int
}

func (s *StructMutator) Mutate(target reflect.Value, comb int) (name string) {
	target = target.Elem()
	nf := target.NumField()
	fn := rand.Intn(nf)
	rf := target.Field(fn)
	tn := target.Type().Name()
	fieldName := target.Type().Field(fn).Name
	fuzzer := fuzz.New()
	fuzzer.Fuzz(rf.Addr().Interface())

	name = fmt.Sprintf(`%s.%s=%v`, tn, fieldName, rf.Interface())
	return
}

func (s *StructMutator) Combinations() int {
	return s.Times
}

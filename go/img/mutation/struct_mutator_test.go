package mutation

import (
	"reflect"
	"testing"
)

func TestStructMutator(t *testing.T) {
	type TestNested struct {
		B int
		C string
	}
	type TestStruct struct {
		A      []byte
		Nested TestNested
	}

	m := &StructMutator{}

	for i := 0; i < 100; i++ {
		ts := &TestStruct{}
		t.Logf("mutated: %s", m.Mutate(reflect.ValueOf(ts), 0))
		t.Logf("res: %+v", ts)
	}
	// t.Fail()
}

package img

import (
	"fmt"
	"reflect"
)

// Mutators:
// - length of chain for certs (0 - 6), incl. generating those certs
// - "correct root", incorrect root, no root
// - random field in struct
// - fixup / don't fixup image (i.e. try to sign, digest, etc.)
// 		- maybe splitup into three different ones?
//

type RecvTest struct {
	Val int
}

func (r *RecvTest) ChangeVal(newVal int) {
	r.Val = newVal
}

func NewMut(target interface{}) *Mutator {
	return &Mutator{
		Target: reflect.TypeOf(target).Elem(),
		Muts:   []reflect.Value{},
		curr:   reflect.ValueOf(target).Elem(),
	}
}

type Mutator struct {
	Target reflect.Type
	Muts   []reflect.Value
	curr   reflect.Value
}

func (m *Mutator) AddMut(fn interface{}) error {
	fv := reflect.ValueOf(fn)
	if fv.Kind() != reflect.Func {
		return fmt.Errorf("failed to add non function mutator %s", fv.Kind())
	}
	m.Muts = append(m.Muts, fv)
	return nil
}

func (m *Mutator) new() error {
	newVal := reflect.Zero(m.Target)
	m.curr.Set(newVal)
	return nil
}

func (m *Mutator) Gen() error {
	m.new()
	for _, fv := range m.Muts {
		fv.Call([]reflect.Value{m.curr.Addr(), reflect.ValueOf(42)})
	}
	return nil
}

func example() {

}

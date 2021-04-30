package mutation

import "reflect"

// Mutator represents a mutation that can be performed.
type Mutator interface {
	Mutate(target reflect.Value, comb int) (name string)
	// How often to call Mutate, until all combinations are exhausted.
	Combinations() int
}

func NewGen(target interface{}) *MutationGen {
	return &MutationGen{
		Target: reflect.ValueOf(target),
		Muts:   make([]Mutator, 0, 10),
	}
}

type MutationGen struct {
	// Pointer as passed in constructor
	Target reflect.Value
	Muts   []Mutator
}

type mutArg func(target reflect.Value) string
type doneFunc func(meta []string)

func (m *MutationGen) Add(mut Mutator) {
	m.Muts = append(m.Muts, mut)
}

func (m *MutationGen) new() {
	t := m.Target.Elem().Type()
	m.Target.Elem().Set(reflect.Zero(t))
}

func (m *MutationGen) Gen(done doneFunc) {
	m.genRec([]mutArg{}, 0, done)
}

func (m *MutationGen) genRec(curr []mutArg, idx int, done doneFunc) {
	if idx < len(m.Muts) {
		mut := m.Muts[idx]
		for i := 0; i < mut.Combinations(); i++ {
			mutFunc := func(target reflect.Value) string {
				return mut.Mutate(target, i)
			}
			curr := append(curr, mutFunc)
			m.genRec(curr, idx+1, done)
		}
	} else {
		m.genRecDone(curr, done)
	}
}

func (m *MutationGen) genRecDone(curr []mutArg, done doneFunc) {
	m.new()
	meta := []string{}
	for _, f := range curr {
		meta = append(meta, f(m.Target))
	}
	done(meta)
}

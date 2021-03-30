package mutation

import "reflect"

// Mutator represents a mutation that can be performed.
type Mutator interface {
	Mutate(target reflect.Value, comb int) (name string)
	// How often to call Mutate, until all combinations are exhausted.
	Combinations() int
}

type MutationGen struct {
	Target   reflect.Type
	Muts     []Mutator
	Children []MutationGen
}

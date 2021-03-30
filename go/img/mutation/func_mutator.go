package mutation

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
)

func NewFunc(fn interface{}, args ...[]interface{}) *FuncMutator {
	f := &FuncMutator{
		Fv:    reflect.ValueOf(fn),
		Args:  args,
		combs: [][]reflect.Value{},
	}
	f.buildCombs([]reflect.Value{}, f.Args)

	return f
}

type FuncMutator struct {
	Fv    reflect.Value
	Args  [][]interface{}
	combs [][]reflect.Value
}

func (f *FuncMutator) buildCombs(curr []reflect.Value, args [][]interface{}) {
	if len(args) == 0 {
		f.combs = append(f.combs, curr)
		return
	}

	for _, arg := range args[0] {
		argv := reflect.ValueOf(arg)
		curr := append(curr, argv)
		f.buildCombs(curr, args[1:])
	}
}

func (f *FuncMutator) Mutate(target reflect.Value, comb int) (name string) {
	fnName := runtime.FuncForPC(f.Fv.Pointer()).Name()
	args := f.combs[comb]
	argS := []string{}
	for _, arg := range args {
		argS = append(argS, fmt.Sprint(arg.Interface()))
	}
	name = fmt.Sprintf("%s(%s)", fnName, strings.Join(argS, ", "))
	t := f.Fv.Type()
	if t.NumIn() > 0 {
		if target.Type().AssignableTo(t.In(0)) {
			args = append([]reflect.Value{target}, args...)
		}
	}
	f.Fv.Call(args)
	return
}

func (f *FuncMutator) Combinations() int {
	return len(f.combs)
}

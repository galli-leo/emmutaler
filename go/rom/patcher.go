package rom

import (
	"fmt"
	"strconv"
)

// Represents an object responsible for patching stuff.
type Patcher interface {
	PatchAt(addr int64, data interface{})
}

// Interface for representing a location we want to patch.
// This can also be multiple locations at the same time.
type PatchingLocation interface {
	Patch(p Patcher)
}

type patchLocation struct {
	addr int64
}

func (s *Symbol) Patch() *patchLocation {
	return &patchLocation{addr: s.Start}
}

func (s *Symbol) PatchOffset(off int64) *patchLocation {
	return &patchLocation{addr: s.Start + off}
}

func (p *patchLocation) Patch(patcher Patcher) {
	patcher.PatchAt(p.addr, nil)
}

func (r *ROM) RawPatch(addr int64, size int64, asm string) {
	chunk := ChunkOfRange(addr, addr+size)
	chunk.RawASM = asm
	r.AppendChunk(chunk)
}

func (r *ROM) PatchSingle(addr int64, asm string) {
	r.RawPatch(addr, 4, asm)
}

func (r *ROM) PatchASM(asm string) *singlePatcher {
	return &singlePatcher{r: r, asm: asm}
}

const multiTmpl = `
.global {{.Label}}
.type {{.Label}},@function
{{.Label}}:
	stp x29, x30, [sp, #-0x10]!
	mov x29, sp
	{{.ASM}}
	ldp x29, x30, [sp], #0x10
	ret
`

var multi = MustTemplate(multiTmpl)

func (r *ROM) PatchMulti(label string, asm string) *singlePatcher {
	actASM := fmt.Sprintf(`bl %s`, label)
	type data struct {
		Label string
		ASM   string
	}
	d := &data{Label: label, ASM: asm}
	addASM := MustExecute(multi, d)
	r.ExtraTextChunks = append(r.ExtraTextChunks, &Chunk{RawASM: addASM})
	return &singlePatcher{
		r:   r,
		asm: actASM,
	}
}

func (r *ROM) PatchMultiNoLink(label string, asm string) *singlePatcher {
	actASM := fmt.Sprintf(`b %s`, label)
	type data struct {
		Label string
		ASM   string
	}
	d := &data{Label: label, ASM: asm}
	addASM := MustExecute(multi, d)
	r.ExtraTextChunks = append(r.ExtraTextChunks, &Chunk{RawASM: addASM})
	return &singlePatcher{
		r:   r,
		asm: actASM,
	}
}

var fnTmpl = `
	{{range $idx, $elem := .Args}}
	mov x{{$idx}}, {{$elem}}
	{{end}}
	adrp x28, {{.Function}}
	add x28, x28, :lo12:{{.Function}}
	blr x28
`

var fn = MustTemplate(fnTmpl)

func (r *ROM) PatchFunction(function string, args ...string) *singlePatcher {
	veneer := function + "_veneer"
	type data struct {
		Function string
		Args     []string
	}
	d := &data{Function: function, Args: args}
	asm := MustExecute(fn, d)
	return r.PatchMulti(veneer, asm)
}

func (r *ROM) PatchFunctionNoLink(function string, args ...string) *singlePatcher {
	veneer := function + "_veneer"
	type data struct {
		Function string
		Args     []string
	}
	d := &data{Function: function, Args: args}
	asm := MustExecute(fn, d)
	return r.PatchMultiNoLink(veneer, asm)
}

func (r *ROM) PatchTmpl(tmplAsm string) *templatePatcher {
	return &templatePatcher{
		r: r,
		tmpl: func(d interface{}) Patcher {
			type data struct {
				Function string
				Args     []string
			}
			asm, _ := TemplateString(tmplAsm, d)
			return r.PatchASM(asm)
		},
	}
}

func (r *ROM) PatchFunctionTmpl(function string, args ...string) *templatePatcher {
	return &templatePatcher{
		r: r,
		tmpl: func(d interface{}) Patcher {
			actArgs := []string{}
			im := d.(*InstrMatch)
			veneer := function + "_veneer_" + strconv.FormatInt(im.Addr, 16)

			for _, arg := range args {
				actArg, _ := TemplateString(arg, d)
				actArgs = append(actArgs, actArg)
			}

			type data struct {
				Function string
				Args     []string
			}
			dd := &data{Function: function, Args: actArgs}
			asm := MustExecute(fn, dd)
			return r.PatchMulti(veneer, asm)
		},
	}
}

type singlePatcher struct {
	r   *ROM
	asm string
}

func (p *singlePatcher) PatchAt(addr int64, data interface{}) {
	p.r.PatchSingle(addr, p.asm)
}

type templatePatcher struct {
	r    *ROM
	tmpl func(data interface{}) Patcher
}

func (p *templatePatcher) PatchAt(addr int64, data interface{}) {
	sp := p.tmpl(data)
	sp.PatchAt(addr, data)
}

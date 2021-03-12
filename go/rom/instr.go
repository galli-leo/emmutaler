package rom

import (
	"fmt"
	"log"
	"os"
	"regexp"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/xerrors"
)

type Instr struct {
	arm64asm.Inst
	Addr int64
	Gas  string
}

type InstrMatch struct {
	Instr
	Groups map[string]string
}

func (i *Instr) String() string {
	return fmt.Sprintf("[0x%08x] %s", i.Addr, i.Gas)
}

func (r *ROM) BuildInstructionDB() error {
	// supported := capstone.Support(int32(capstone.ARCH_ARM64))
	// log.Printf("ARM supported: %d", supported)
	bin, err := os.ReadFile(r.inputPath)
	if err != nil {
		return xerrors.Errorf("failed to read input file %s: %w", r.inputPath, err)
	}
	// cs, err := capstone.NewCS(capstone.ARCH_ARM64, capstone.OPT_DETAIL)
	// if err != nil {
	// 	return xerrors.Errorf("failed to create capstone: %w", err)
	// }

	for ea := int64(0); ea < r.DataFileStart(); ea += 4 {
		binInst := bin[ea : ea+4]
		// actAddr := r.meta.LinkerInfo.Text.Start + uint64(ea)
		// ii := cs.Disasm(binInst, actAddr)
		// ii.Deref()
		// log.Printf("%s", ii)
		inst, err := arm64asm.Decode(binInst)
		if err != nil {
			continue
		}
		i := &Instr{
			Inst: inst,
			Addr: ea,
			Gas:  arm64asm.GNUSyntax(inst),
		}
		// log.Printf("[0x%08x] %s", ea, arm64asm.GNUSyntax(inst))
		r.Instructions = append(r.Instructions, i)
	}
	return nil
}

func (r *ROM) FindInstruction(re string) []*InstrMatch {
	re = "(?i)" + re
	cmpRe, err := regexp.Compile(re)
	if err != nil {
		log.Fatalf("Failed to compile regex %s: %s", re, err)
	}
	ret := []*InstrMatch{}
	for _, instr := range r.Instructions {
		match := cmpRe.FindStringSubmatch(instr.Gas)
		if len(match) > 0 {
			result := make(map[string]string)
			for i, name := range cmpRe.SubexpNames() {
				if i != 0 && name != "" {
					result[name] = match[i]
				}
			}
			ret = append(ret, &InstrMatch{
				Instr:  *instr,
				Groups: result,
			})
		}
	}
	return ret
}

func (r *ROM) PatchInstruction(re string) *instrPatcher {
	instr := r.FindInstruction(re)
	return &instrPatcher{instr: instr}
}

type instrPatcher struct {
	instr []*InstrMatch
}

func (p *instrPatcher) Patch(patcher Patcher) {
	for _, instr := range p.instr {
		patcher.PatchAt(instr.Addr, instr)
	}
}

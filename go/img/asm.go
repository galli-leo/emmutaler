package img

import (
	"fmt"
	"log"

	asm "github.com/twitchyliquid64/golang-asm"
	"github.com/twitchyliquid64/golang-asm/obj"
	"github.com/twitchyliquid64/golang-asm/obj/arm64"
	"github.com/twitchyliquid64/golang-asm/obj/x86"
)

const (
	RetValidPayload   = 420
	RetInvalidPayload = 69
)

func noop(builder *asm.Builder) *obj.Prog {
	prog := builder.NewProg()
	prog.As = x86.ANOPL
	prog.From.Type = obj.TYPE_REG
	prog.From.Reg = x86.REG_AX
	return prog
}

func addImmediateByte(builder *asm.Builder, in int32) *obj.Prog {
	prog := builder.NewProg()
	prog.As = x86.AADDB
	prog.To.Type = obj.TYPE_REG
	prog.To.Reg = x86.REG_AL
	prog.From.Type = obj.TYPE_CONST
	prog.From.Offset = int64(in)
	return prog
}

func movImmediateByte(builder *asm.Builder, reg int16, in int32) *obj.Prog {
	prog := builder.NewProg()
	prog.As = x86.AMOVB
	prog.To.Type = obj.TYPE_REG
	prog.To.Reg = reg
	prog.From.Type = obj.TYPE_CONST
	prog.From.Offset = int64(in)
	return prog
}

func Trying() {
	b, _ := asm.NewBuilder("amd64", 64)
	b.AddInstruction(noop(b))
	b.AddInstruction(movImmediateByte(b, x86.REG_AL, 16))
	b.AddInstruction(addImmediateByte(b, 16))
	log.Printf("Bin: %x\n", b.Assemble())
}

var retBytes = []byte{0xc0, 0x03, 0x5f, 0xd6}

func BuildSimplePayload(ret int) ([]byte, error) {
	Trying()
	r := []byte{}
	b, err := asm.NewBuilder("arm64", 0)
	if err != nil {
		return r, fmt.Errorf("failed to create builder: %w", err)
	}
	nop := b.NewProg()
	nop.As = arm64.ANOOP
	b.AddInstruction(nop)
	movI := b.NewProg()
	movI.As = arm64.AMOVD
	movI.To.Type = obj.TYPE_REG
	movI.To.Reg = arm64.REG_R0
	movI.From.Type = obj.TYPE_CONST
	movI.From.Offset = int64(ret)
	b.AddInstruction(movI)

	nop = b.NewProg()
	nop.As = arm64.ANOOP
	b.AddInstruction(nop)
	// rt := b.NewProg()
	// rt.As = obj.ARET
	// // rt.Pos = src.NoXPos
	// b.AddInstruction(rt)
	r = b.Assemble()
	r = r[:len(r)-8] // cut off last 4 bytes.
	r = append(r, retBytes...)
	log.Printf("Simple Payload: %x", r)
	return r, nil
}

package rom

// TODO: This whole thing.
// Unify with chunk?
type SectionPerm int

const (
	Read SectionPerm = 1 << iota
	Write
	Exec
)

func (sp *SectionPerm) GAS() string {
	ret := ""
	if *sp&Read == Read {
		ret += "a"
	}
	if *sp&Write == Write {
		ret += "w"
	}
	if *sp&Exec == Exec {
		ret += "x"
	}
	return ret
}

// Section is associated with a section in the final assembly / binary.
type Section struct {
	Permissions SectionPerm
}

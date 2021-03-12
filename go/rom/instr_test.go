package rom

import "testing"

func TestInstructionDB(t *testing.T) {
	r := FromPath(testFile)
	err := r.LoadMeta()
	if err != nil {
		t.Fatalf("Failed to load meta: %s", err)
	}
	err = r.BuildInstructionDB()
	if err != nil {
		t.Fatalf("Couldn't build instruction db: %s", err)
	}
	instr := r.FindInstruction("dc zva, ")
	t.Fatalf("Found instr: %s", instr[0].Inst.Args)
	if len(instr) > 0 {
		t.Fatalf("Expected some disable interrupt instructions!")
	}
}

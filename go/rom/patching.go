package rom

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func (r *ROM) DoPatch() {
	symb := r.GetSymbols()
	// TODO: Nicer syntax here?
	nopper := r.PatchASM("nop")
	symb.rom_start.PatchOffset(0xc).Patch(nopper)
	symb.rom_main.PatchOffset(40).Patch(nopper)
	symb.rom_main.PatchOffset(48).Patch(r.PatchFunction("arch_cpu_init_handler"))

	r.RawPatch(symb.rom_aIboot447900100.Start+176, 8, ".quad 0x19C00C000")
	// symb.rom_aIboot447900100.PatchOffset(176).Patch(r.PatchASM(".quad 0x19C00C000"))

	// Patch out interrupt disabling instructions.
	r.PatchInstruction("msr daifset, #0xf").Patch(nopper)
	r.PatchInstruction("msr daifset, #0x3").Patch(nopper)
	r.PatchInstruction("msr spsel, #0x0").Patch(nopper)
	r.PatchInstruction("msr daifclr, #0x3").Patch(nopper)
	r.PatchInstruction("blraaz ").Patch(r.PatchTmpl("blr {{(index .Args 0)}}"))
	symb.rom__bzero.PatchOffset(0x18).Patch(r.PatchASM("cmp x2, #0x40000"))
	symb.rom_report_no_boot_image.PatchOffset(0).Patch(r.PatchFunctionNoLink("report_no_boot_image_handler"))
	symb.rom_some_kind_of_report.PatchOffset(0).Patch(r.PatchFunctionNoLink("some_kind_of_report_handler"))
	certPath := filepath.Join(filepath.Dir(r.inputPath), "..", "certs", "root_ca.der")
	certData, err := os.ReadFile(certPath)
	if err != nil {
		log.Fatalf("Failed to read root cert: %s", err)
	}
	root_ca_start := symb.rom_root_ca.Start
	r.RawPatch(root_ca_start, int64(len(certData)), fmt.Sprintf(`.incbin "%s"`, certPath))

	symb.rom__panic.PatchOffset(0).Patch(r.PatchFunctionNoLink("panic_handler"))
	symb.rom_heap_panic.PatchOffset(0).Patch(r.PatchFunctionNoLink("heap_panic_handler"))
	// symb.rom_start.PatchOffset(0x13E98).Patch(r.PatchASM("blr x8")) // For now 13EB8
	// symb.rom_start.PatchOffset(0x13EB8).Patch(r.PatchASM("blr x8"))
	// Handle exception vector
	r.PatchInstruction("msr s3_0_c12_c0_0,").Patch(r.PatchFunctionTmpl("vbar_el1_handler", "{{(index .Args 1)}}"))
}

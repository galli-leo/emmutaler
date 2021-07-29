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
	// symb.rom_start.PatchOffset(0xc).Patch(nopper)
	symb.rom_main.PatchOffset(40).Patch(nopper)
	symb.rom_main.PatchOffset(48).Patch(r.PatchFunction("arch_cpu_init_handler"))

	// r.RawPatch(symb.rom_aIboot447900100.Start+176, 8, ".quad 0x19C00C000")
	// symb.rom_aIboot447900100.PatchOffset(176).Patch(r.PatchASM(".quad 0x19C00C000"))

	// Patch out interrupt disabling instructions.
	r.PatchInstruction("msr daifset, #0xf").Patch(nopper)
	r.PatchInstruction("msr daifset, #0x3").Patch(nopper)
	r.PatchInstruction("msr spsel, #0x0").Patch(nopper)
	r.PatchInstruction("msr daifclr, #0x3").Patch(nopper)
	r.PatchInstruction("blraaz ").Patch(r.PatchTmpl("blr {{(index .Args 0)}}"))
	// s3_3_c14_c0_1 = cntpct_el0
	r.PatchInstruction("mrs x0, s3_3_c14_c0_1").Patch(r.PatchFunctionNoLink("timer_get_ticks"))
	symb.rom__bzero.PatchOffset(0x18).Patch(r.PatchASM("cmp x2, #0x40000"))
	symb.rom_report_no_boot_image.PatchOffset(0).Patch(r.PatchFunctionNoLink("report_no_boot_image_handler"))
	symb.rom_some_kind_of_report.PatchOffset(0).Patch(r.PatchFunctionNoLink("some_kind_of_report_handler"))
	symb.rom_synopsys_otg_controller_init.PatchOffset(0).Patch(r.PatchFunctionNoLink("emmutaler_controller_init"))
	symb.rom_platform_get_entropy.PatchOffset(0).Patch(r.PatchFunctionNoLink("platform_get_entropy"))
	symb.rom_platform_get_sep_nonce.PatchOffset(0).Patch(r.PatchFunctionNoLink("platform_get_sep_nonce"))
	certPath := filepath.Join(filepath.Dir(r.inputPath), "..", "certs", "root_ca.der")
	certData, err := os.ReadFile(certPath)
	if err != nil {
		log.Fatalf("Failed to read root cert: %s", err)
	}
	root_ca_start := symb.rom_root_ca.Start
	r.RawPatch(root_ca_start, int64(len(certData)), fmt.Sprintf(`.incbin "%s"`, certPath))

	// symb.rom__panic.PatchOffset(0).Patch(r.PatchFunctionNoLink("panic_handler"))
	// TODO: Don't hardcode!
	loc := &patchLocation{addr: 0x000000000000f0fc}
	loc.Patch(r.PatchFunctionNoLink("panic_handler"))
	symb.rom_heap_panic.PatchOffset(0).Patch(r.PatchFunctionNoLink("heap_panic_handler"))
	// symb.rom_start.PatchOffset(0x13E98).Patch(r.PatchASM("blr x8")) // For now 13EB8
	// symb.rom_start.PatchOffset(0x13EB8).Patch(r.PatchASM("blr x8"))
	// Handle exception vector
	r.PatchInstruction("msr s3_0_c12_c0_0,").Patch(r.PatchFunctionTmpl("vbar_el1_handler", "{{(index .Args 1)}}"))

	symb.rom_heap_alloc.PatchOffset(0).Patch(r.PatchFunctionNoLink("checked_heap_alloc"))
	symb.rom_heap_free.PatchOffset(0).Patch(r.PatchFunctionNoLink("checked_heap_free"))
	symb.rom_heap_memalign.PatchOffset(0).Patch(r.PatchFunctionNoLink("checked_heap_memalign"))

	if GenConf.AllowOOB {
		// Patch DER functions to not check length!
		// r.PatchDERItem(symb.rom_DERDecodeItemPartialBuffer)
		// symb.rom_DERDecodeItemPartialBuffer_0.PatchOffset(4).Patch(r.PatchASM("mov x2, #0x1"))
		// symb.rom_DERDecodeItemPartialBuffer_0.PatchOffset(8).Patch(r.PatchASM("b .+12"))
		//r.PatchDERItem(symb.rom_DERDecodeItemPartialBuffer_0)
	}
}

func (r *ROM) PatchDERItem(symb Symbol) {
	symb.PatchOffset(4).Patch(r.PatchASM("mov x2, #0x2000000"))
	symb.PatchOffset(8).Patch(r.PatchASM("b .+12")) // always branch
}

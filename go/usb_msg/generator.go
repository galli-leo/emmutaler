package usbmsg

import (
	"fmt"
	"os"
	"path/filepath"
)

func NewGen(out, img string) *Generator {
	return &Generator{
		OutDir: out,
		ImgDir: img,
	}
}

type Generator struct {
	OutDir string
	ImgDir string
	e      error
}

// Here we run all generators.
func (g *Generator) Gen() error {
	// This should be a perfectly valid sequence of usb messages!
	// Too big!
	// g.Seq("test_img_upload", func(s *Sequence) {
	// 	s.AppendDFUSetup(DFUGetState, Device2Host, 0)
	// 	s.AppendDFUSetup(DFUGetStatus, Device2Host, 0)
	// 	imgFile := filepath.Join(g.ImgDir, "test.img4")
	// 	data, err := os.ReadFile(imgFile)
	// 	if err != nil {
	// 		s.e = fmt.Errorf("failed to read image file %s: %w", imgFile, err)
	// 		return
	// 	}

	// 	// For some unknown reason, they remove the last 0x10 bytes.
	// 	// Add this as padding here!
	// 	fileSuff := [0x10]byte{}
	// 	data = append(data, fileSuff[:]...)

	// 	s.AppendDFU(DFUDnload, Host2Device, data)
	// 	// change state to MANIFEST_SYNC
	// 	s.AppendDFUSetup(DFUDnload, Host2Device, 0)
	// 	// Needs to happen twice, don't ask my why lol
	// 	// Change state to MANIFEST
	// 	s.AppendDFUSetup(DFUGetStatus, Device2Host, 0)
	// 	// Change state to MANIFEST_WAIT_RESET
	// 	s.AppendDFUSetup(DFUGetStatus, Device2Host, 0)
	// 	s.Append(USBReset)
	// })

	// Causes panic :(
	// g.Seq("some_messages", func(s *Sequence) {
	// 	// s.AppendDFUSetup(DFUDnload, Host2Device, 0)
	// 	s.AppendDFUSetup(DFUGetStatus, Device2Host, 0)
	// 	s.AppendDFUSetup(DFUAbort, Device2Host, 0)
	// 	// s.AppendDFUSetup(DFUGetStatus, Device2Host, 0)
	// 	// s.AppendDFUSetup(DFUGetStatus, Host2Device, 0)
	// 	s.AppendDFUSetup(DFUDetach, Device2Host, 0)

	// 	s.AppendGetDescriptor(Device, 0, 0)
	// 	for i := 0; i < 9; i++ {
	// 		s.AppendGetDescriptor(String, uint8(i), 0)
	// 	}
	// })

	g.Seq("short_upload", func(s *Sequence) {
		s.AppendDFUSetup(DFUGetState, Device2Host, 0)
		s.AppendDFUSetup(DFUGetStatus, Device2Host, 0)
		data := []byte{0x90, 0x90, 0x90, 0x90, 0x90}
		// For some unknown reason, they remove the last 0x10 bytes.
		// Add this as padding here!
		fileSuff := [0x10]byte{}
		data = append(data, fileSuff[:]...)

		s.AppendDFU(DFUDnload, Host2Device, data)
		// change state to MANIFEST_SYNC
		s.AppendDFUSetup(DFUDnload, Host2Device, 0)
		// Needs to happen twice, don't ask my why lol
		// Change state to MANIFEST
		s.AppendDFUSetup(DFUGetStatus, Device2Host, 0)
		// Change state to MANIFEST_WAIT_RESET
		s.AppendDFUSetup(DFUGetStatus, Device2Host, 0)
		s.Append(USBReset)
	})

	for i := 0; i < 10; i++ {
		g.Seq(fmt.Sprintf("str_desc_%d", i), func(s *Sequence) {
			s.AppendGetDescriptor(String, uint8(i), 0)
		})
	}

	g.Seq("get_desc", func(s *Sequence) {
		s.AppendGetDescriptor(Device, 0, 0)
		s.AppendGetDescriptor(DeviceQualifier, 0, 0)
		s.AppendGetDescriptor(OtherSpeedConfiguration, 0, 0)
		s.AppendGetDescriptor(Configuration, 0, 0)
	})

	g.Seq("std_usb_dev2host", func(s *Sequence) {
		s.AppendStandard(GetConfiguration, RecipientDevice, Device2Host, 0, 0, 0)
		s.AppendStandard(GetInterface, RecipientDevice, Device2Host, 0, 0, 0)
		s.AppendStandard(GetStatus, RecipientDevice, Device2Host, 0, 0, 0)
	})

	g.Seq("std_usb_host2dev", func(s *Sequence) {
		s.AppendStandard(ClearFeature, RecipientDevice, Host2Device, 0, 0, 0)
		s.AppendStandard(SetFeature, RecipientDevice, Host2Device, 0, 0, 0)
		s.AppendStandard(SetAddress, RecipientDevice, Host2Device, 0, 0, 0)
		s.AppendStandard(SetConfiguration, RecipientDevice, Host2Device, 0, 0, 0)
		s.AppendStandard(SetInterface, RecipientDevice, Host2Device, 0, 0, 0)
	})

	g.Seq("events", func(s *Sequence) {
		s.Append(CableConnected)
		s.Append(CableDisconnected)
		s.Append(CableConnected)
	})

	// g.Seq("exploit", func(s *Sequence) {
	// 	// s.AppendGetDescriptor(Device, 0, 0)
	// 	// s.AppendGetDescriptor(String, 4, 0xc1)
	// 	// for i := 0; i < 10; i++ {
	// 	// 	s.AppendGetDescriptor(String, 4, 0xc0)
	// 	// }
	// 	// s.AppendGetDescriptor(String, 4, 0xc1)

	// 	s.AppendDFUSetup(DFUDnload, Host2Device, 0x800)
	// 	data := [0x40]byte{}
	// 	for i := 0; i < 0x40; i++ {
	// 		data[i] = 0x90
	// 	}
	// 	// for i := 0; i < 0x20; i++ {
	// 	// 	s.Append(Data(data[:]))
	// 	// }
	// 	// s.Append(Data(data[:]))
	// 	s.AppendDFUSetup(DFUCLRStatus, Host2Device, 0)
	// 	// s.Append(USBReset)
	// 	// s.Append(USBEnumDone)
	// 	// s.AppendGetDescriptor(Device, 0, 0)
	// 	// s.AppendGetDescriptor(String, 4, 0)
	// 	// s.AppendGetDescriptor(String, 1, 0)
	// 	// s.AppendGetDescriptor(String, 2, 0)
	// 	stp := &Setup{
	// 		RequestType: 0,
	// 		Recipient:   0,
	// 		Direction:   0,
	// 		Request:     0,
	// 		Index:       0,
	// 		Length:      0x800,
	// 		Value:       0,
	// 	}
	// 	_ = stp
	// 	// s.Append(stp)
	// 	for i := 0; i < 0x1; i++ {
	// 		s.Append(Data(data[:]))
	// 	}
	// 	// Theoretically, heap should be corrupted now!
	// 	s.AppendDFUSetup(DFUAbort, Device2Host, 0)
	// })

	return g.e
}

func (g *Generator) Seq(name string, fill func(s *Sequence)) {
	if g.e != nil {
		return
	}
	filename := filepath.Join(g.OutDir, name+".seq")
	outf, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0777)
	if err != nil {
		g.e = err
		return
	}

	seq := &Sequence{
		w: outf,
	}
	fill(seq)
	if seq.Error() != nil {
		g.e = err
	}
}

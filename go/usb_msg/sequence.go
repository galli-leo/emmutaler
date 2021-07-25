package usbmsg

import "io"

type DFURequest uint8

const (
	DFUDetach DFURequest = iota
	DFUDnload
	DFUUpload
	DFUGetStatus
	DFUCLRStatus
	DFUGetState
	DFUAbort
)

/// Sequence is a sequence of messages
/// They are written to disk
type Sequence struct {
	w io.Writer
	e error
}

func (s *Sequence) Append(msg USBMessage) {
	// Fail if we already have an error
	if s.e != nil {
		return
	}

	s.e = WriteMessage(msg, s.w)
}

func (s *Sequence) AppendDFUSetup(req DFURequest, dir Direction, size uint16) {
	stp := &Setup{
		RequestType: Class,
		Recipient:   RecipientInterface,
		Direction:   dir,
		Request:     uint8(req),
		Index:       0,
		Value:       0,
		Length:      size,
	}
	s.Append(stp)
}

const DFU_MAX_TRANSFER_SIZE = 2048

/// Fragment data into size chunks and call frag for every chunk.
func (s *Sequence) Fragment(data []byte, size int, frag func(frag []byte)) {
	curr := 0
	left := len(data)
	for left > 0 {
		end := curr + size
		if end > len(data) {
			end = len(data)
		}

		frag(data[curr:end])

		curr += size
		left -= size
	}
}

func (s *Sequence) AppendDFU(req DFURequest, dir Direction, data []byte) {
	// Fragment data into DFU_MAX_TRANSFER_SIZE setup + data messages

	s.Fragment(data, DFU_MAX_TRANSFER_SIZE, func(largeFrag []byte) {
		s.AppendDFUSetup(req, dir, uint16(len(largeFrag)))

		// Fragment data into EP0_MAX_PACKET_SIZE messages
		s.Fragment(largeFrag, EP0_MAX_PACKET_SIZE, func(frag []byte) {
			s.Append(Data(frag))
		})
	})
}

func (s *Sequence) AppendStandard(req StandardRequestType, recv RecipientType, dir Direction, idx uint16, val uint16, size uint16) {
	stp := &Setup{
		RequestType: Standard,
		Recipient:   recv,
		Direction:   dir,
		Request:     uint8(req),
		Index:       idx,
		Value:       val,
		Length:      size,
	}
	s.Append(stp)
}

func (s *Sequence) AppendGetDescriptor(dt DescriptorType, idx uint8, langId uint16) {
	s.AppendStandard(GetDescriptor, RecipientDevice, Device2Host, langId, (uint16(dt)<<8)|uint16(idx), 0x100)
}

func (s *Sequence) Error() error {
	return s.e
}

package usbmsg

import (
	"encoding/binary"
	"time"
)

type Setup struct {
	RequestType RequestType
	Recipient   RecipientType
	Direction   Direction
	Request     uint8
	Index       uint16
	Length      uint16
	Value       uint16
}

func (s *Setup) GetType() Type {
	return SETUP
}

func (s *Setup) GetSize() uint32 {
	return 8
}

func (s *Setup) GetData() [EP0_MAX_PACKET_SIZE]byte {
	out := [EP0_MAX_PACKET_SIZE]byte{}
	out[0] = byte(s.RequestType) | byte(s.Recipient) | byte(s.Direction)
	out[1] = s.Request
	binary.LittleEndian.PutUint16(out[2:4], s.Value)
	binary.LittleEndian.PutUint16(out[4:6], s.Index)
	binary.LittleEndian.PutUint16(out[6:8], s.Length)
	return out
}

// TODO: Careful, byte should not be larger than EP0_MAX_PACKET_SIZE
type Data []byte

func (d Data) GetType() Type {
	return DATA
}

func (d Data) GetSize() uint32 {
	return uint32(len(d))
}

func (d Data) GetData() [EP0_MAX_PACKET_SIZE]byte {
	out := [EP0_MAX_PACKET_SIZE]byte{}
	copy(out[:], d)
	return out
}

type USBEvent uint8

const (
	CableConnected USBEvent = iota
	CableDisconnected
	USBReset
	USBEnumDone
)

func (e USBEvent) GetType() Type {
	return EVENT
}

func (e USBEvent) GetSize() uint32 {
	return 1
}

func (e USBEvent) GetData() [EP0_MAX_PACKET_SIZE]byte {
	out := [EP0_MAX_PACKET_SIZE]byte{byte(e), 0}
	return out
}

type Sleep time.Duration

func (s Sleep) GetType() Type {
	return SLEEP
}

func (s Sleep) GetSize() uint32 {
	return 8
}

func (s Sleep) GetData() [EP0_MAX_PACKET_SIZE]byte {
	dur := time.Duration(s)
	msecs := dur.Milliseconds()
	out := [EP0_MAX_PACKET_SIZE]byte{}
	binary.LittleEndian.PutUint64(out[:], uint64(msecs))
	return out
}

type Nop struct{}

func (n Nop) GetType() Type {
	return NOP
}

func (n Nop) GetSize() uint32 {
	return 0
}

func (n Nop) GetData() [EP0_MAX_PACKET_SIZE]byte {
	return [EP0_MAX_PACKET_SIZE]byte{}
}

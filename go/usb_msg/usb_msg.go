package usbmsg

import (
	"fmt"
	"io"
)

type Type uint32

const (
	SETUP Type = iota
	DATA
	EVENT
	SLEEP
	NOP
)

const EP0_MAX_PACKET_SIZE = 0x40
const USB_MESSAGE_SIZE = EP0_MAX_PACKET_SIZE + 2

type USBMessage interface {
	/// Get the type of the message
	GetType() Type

	/// Get the size of the message
	GetSize() uint32

	/// Get the data of the message (Can be at max EP0_MAX_PACKET_SIZE)!
	GetData() [EP0_MAX_PACKET_SIZE]byte
}

func WriteMessage(msg USBMessage, w io.Writer) error {
	buf := [USB_MESSAGE_SIZE]byte{}
	// binary.LittleEndian.PutUint32(buf[:], uint32(msg.GetType()))
	// binary.LittleEndian.PutUint32(buf[4:], msg.GetSize())
	buf[0] = byte(msg.GetType())
	buf[1] = byte(msg.GetSize())
	data := msg.GetData()
	copy(buf[2:], data[:])
	n, err := w.Write(buf[:])
	if err != nil {
		return err
	}
	if n != USB_MESSAGE_SIZE {
		return fmt.Errorf("failed to write all of the message, %d", n)
	}
	return nil
}

package usbmsg

type DescriptorType uint8

const (
	Device DescriptorType = iota + 1
	Configuration
	String
	Interface
	Endpoint
	DeviceQualifier
	OtherSpeedConfiguration
)

type EndpointType uint8

const (
	Control EndpointType = iota
	Isochronous
	Bulk
	Interrupt
)

type StandardRequestType uint8

const (
	GetStatus StandardRequestType = iota
	ClearFeature
	_
	SetFeature
	_
	SetAddress
	GetDescriptor
	SetDescriptor
	GetConfiguration
	SetConfiguration
	GetInterface
	SetInterface
)

type RequestType uint8

const (
	Standard RequestType = 0x00
	Class    RequestType = 0x20
	Vendor   RequestType = 0x40
	Mask     RequestType = 0x60
)

type RecipientType uint8

const (
	RecipientDevice RecipientType = iota
	RecipientInterface
	RecipientEndpoint
	RecipientOther
	RecipientMask RecipientType = 0x1f
)

type Direction uint8

const (
	Device2Host   Direction = 0x80
	Host2Device   Direction = 0x00
	DirectionMask Direction = 0x80
)

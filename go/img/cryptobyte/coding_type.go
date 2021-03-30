package cryptobyte

import (
	"reflect"

	"github.com/galli-leo/emmutaler/img/cryptobyte/asn1"
)

type CodingType int

const (
	UnknownType CodingType = iota
	IntType
	BoolType
	StringType
	BytesType
	StructType
	MapType
	ArrayType
)

func (c CodingType) AcceptedTags() []asn1.Tag {
	switch c {
	case IntType:
		return []asn1.Tag{asn1.ENUM, asn1.INTEGER}
	case StringType:
		return []asn1.Tag{asn1.GeneralString, asn1.IA5String, asn1.T61String, asn1.PrintableString, asn1.UTF8String}
	case BytesType:
		return []asn1.Tag{asn1.BIT_STRING, asn1.OCTET_STRING, asn1.OBJECT_IDENTIFIER}
	case BoolType:
		return []asn1.Tag{asn1.BOOLEAN}
	case StructType:
		return []asn1.Tag{asn1.SEQUENCE, asn1.SET}
	case MapType:
		return []asn1.Tag{asn1.SET}
	case ArrayType:
		return []asn1.Tag{asn1.SEQUENCE}
	}

	return []asn1.Tag{}
}

func (c CodingType) EncodedTag() asn1.Tag {
	switch c {
	case IntType:
		return asn1.INTEGER
	case StringType:
		return asn1.IA5String
	case BytesType:
		return asn1.OCTET_STRING
	case BoolType:
		return asn1.BOOLEAN
	case StructType:
		return asn1.SEQUENCE
	case MapType:
		return asn1.SET
	case ArrayType:
		return asn1.SEQUENCE
	}

	return initTag
}

func CodingTypeOfKind(v reflect.Value) CodingType {
	switch v.Kind() {
	case reflect.Array, reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return BytesType
		}

		return ArrayType
	case reflect.Bool:
		return BoolType
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uint8:
		return IntType
	case reflect.String:
		return StringType
	case reflect.Struct:
		return StructType
	// Should only occur in encoding context, since otherwise pointer / interface will be dereferenced in indirect!
	case reflect.Ptr, reflect.Interface:
		return CodingTypeOfKind(v.Elem())
	case reflect.Map:
		return MapType
	}

	return UnknownType
}

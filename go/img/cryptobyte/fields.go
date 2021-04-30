package cryptobyte

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/galli-leo/emmutaler/img/cryptobyte/asn1"
)

// ASN.1 has IMPLICIT and EXPLICIT tags, which can be translated as "instead
// of" and "in addition to". When not specified, every primitive type has a
// default tag in the UNIVERSAL class.
//
// For example: a BIT STRING is tagged [UNIVERSAL 3] by default (although ASN.1
// doesn't actually have a UNIVERSAL keyword). However, by saying [IMPLICIT
// CONTEXT-SPECIFIC 42], that means that the tag is replaced by another.
//
// On the other hand, if it said [EXPLICIT CONTEXT-SPECIFIC 10], then an
// /additional/ tag would wrap the default tag. This explicit tag will have the
// compound flag set.
//
// (This is used in order to remove ambiguity with optional elements.)
//
// You can layer EXPLICIT and IMPLICIT tags to an arbitrary depth, however we
// don't support that here. We support a single layer of EXPLICIT or IMPLICIT
// tagging with tag strings on the fields of a structure.

// fieldParameters is the parsed representation of tag string from a structure field.
type fieldParameters struct {
	optional   bool     // true iff the field is OPTIONAL
	tag        asn1.Tag // the EXPLICIT or IMPLICIT tag (maybe nil).
	stringType int      // the string tag to use when marshaling.
	timeType   int      // the time tag to use when marshaling.
	set        bool     // true iff this should be encoded as a SET
	omitEmpty  bool     // true iff this should be omitted if empty when marshaling.
	nested     bool     // true iff it is nested inside another layer, e.g. octet string.
	skip       bool     // true iff we should skip i.e. not encode this field.
	// Invariants:
	//   if explicit is set, tag is non-nil.
}

// Given a tag string with the format specified in the package comment,
// parseFieldParameters will parse it into a fieldParameters structure,
// ignoring unknown parts of the string.
func parseFieldParameters(str string) (ret fieldParameters) {
	var part string
	ret.tag = initTag
	for len(str) > 0 {
		// This loop uses IndexByte and explicit slicing
		// instead of strings.Split(str, ",") to reduce allocations.
		i := strings.IndexByte(str, ',')
		if i < 0 {
			part, str = str, ""
		} else {
			part, str = str[:i], str[i+1:]
		}
		switch {
		case part == "optional":
			ret.optional = true
		case part == "generalized":
			ret.tag = asn1.GeneralizedTime
		case part == "utc":
			ret.tag = asn1.UTCTime
		case part == "ia5":
			ret.tag = asn1.IA5String
		case part == "printable":
			ret.tag = asn1.PrintableString
		case part == "utf8":
			ret.tag = asn1.UTF8String
		case part == "nested":
			ret.nested = true
		case strings.HasPrefix(part, "tag:"):
			i, err := strconv.Atoi(part[4:])
			if err == nil {
				ret.tag = asn1.Tag(i)
			}
		case strings.HasPrefix(part, "ctag:"):
			ret.tag = asn1.FromChar(part[5:])
		case part == "set":
			ret.set = true
			ret.tag = asn1.SET
		case part == "application":
			ret.tag = ret.tag.WithClass(asn1.ClassApplication)
		case part == "private":
			ret.tag = ret.tag.WithClass(asn1.ClassPrivate)
		case part == "context":
			ret.tag = ret.tag.WithClass(asn1.ClassContextSpecific)
		case part == "constructed":
			ret.tag = ret.tag.WithMethod(asn1.MethodConstructed)
		case part == "omitempty":
			ret.omitEmpty = true
		case part == "skip":
			ret.skip = true
		}
	}
	return
}

type structField struct {
	reflect.StructField
	v      reflect.Value
	params fieldParameters
}

func getStructFields(v reflect.Value) []structField {
	ret := []structField{}
	for i := 0; i < v.NumField(); i++ {
		sf := structField{StructField: v.Type().Field(i), v: v.Field(i)}
		sf.params = parseFieldParameters(sf.Tag.Get("asn1"))
		ret = append(ret, sf)
	}
	return ret
}

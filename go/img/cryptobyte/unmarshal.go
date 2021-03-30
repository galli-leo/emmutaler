package cryptobyte

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/galli-leo/emmutaler/img/cryptobyte/asn1"
)

const initTag = asn1.Tag(0)

type Unmarshaler interface {
	UnmarshalASN1(*String) error
}

func Unmarshal(data []byte, v interface{}) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return fmt.Errorf("asn1: expected ptr not %s", reflect.TypeOf(v))
	}
	s := String(data)
	d := newDecodeCtx(rv, &s, initTag)
	return d.decode()
}

func newDecodeCtx(v reflect.Value, s *String, tag asn1.Tag) *decodeCtx {
	d := &decodeCtx{
		v:   v,
		s:   s,
		tag: tag,
	}

	return d
}

type decodeCtx struct {
	parent *decodeCtx
	name   string
	v      reflect.Value
	s      *String
	c      CodingType
	// tag we want to decode. Can be set explicitly via struct fields.
	tag asn1.Tag
}

func (d *decodeCtx) fillTag() error {
	accepted := d.c.AcceptedTags()
	for _, acc := range accepted {
		if d.s.PeekASN1Tag(acc) {
			d.tag = acc
			return nil
		}
	}
	var s String
	var t asn1.Tag
	d.s.ReadAnyASN1(&s, &t)
	return d.err("failed to read any accepted tag, curr is: %s", t)
}

// indirect walks down v allocating pointers as needed,
// until it gets to a non-pointer.
// If it encounters an Unmarshaler, indirect stops and returns that.
// If decodingNull is true, indirect stops at the first settable pointer so it
// can be set to nil.
func indirect(v reflect.Value) (Unmarshaler, reflect.Value) {
	// Issue #24153 indicates that it is generally not a guaranteed property
	// that you may round-trip a reflect.Value by calling Value.Addr().Elem()
	// and expect the value to still be settable for values derived from
	// unexported embedded struct fields.
	//
	// The logic below effectively does this when it first addresses the value
	// (to satisfy possible pointer methods) and continues to dereference
	// subsequent pointers as necessary.
	//
	// After the first round-trip, we set v back to the original value to
	// preserve the original RW flags contained in reflect.Value.
	v0 := v
	haveAddr := false

	// If v is a named type and is addressable,
	// start with its address, so that if the type has pointer methods,
	// we find them.
	if v.Kind() != reflect.Ptr && v.Type().Name() != "" && v.CanAddr() {
		haveAddr = true
		v = v.Addr()
	}
	for {
		// Load value from interface, but only if the result will be
		// usefully addressable.
		if v.Kind() == reflect.Interface && !v.IsNil() {
			e := v.Elem()
			if e.Kind() == reflect.Ptr && !e.IsNil() && (e.Elem().Kind() == reflect.Ptr) {
				haveAddr = false
				v = e
				continue
			}
		}

		if v.Kind() != reflect.Ptr {
			break
		}

		if v.CanSet() {
			break
		}

		// Prevent infinite loop if v is an interface pointing to its own address:
		//     var v interface{}
		//     v = &v
		if v.Elem().Kind() == reflect.Interface && v.Elem().Elem() == v {
			v = v.Elem()
			break
		}
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		if v.Type().NumMethod() > 0 && v.CanInterface() {
			if u, ok := v.Interface().(Unmarshaler); ok {
				return u, reflect.Value{}
			}
		}

		if haveAddr {
			v = v0 // restore original value after round-trip Value.Addr().Elem()
			haveAddr = false
		} else {
			v = v.Elem()
		}
	}
	return nil, v
}

func (d *decodeCtx) actDecode() error {
	u, v := indirect(d.v)
	if u != nil {
		if err := u.UnmarshalASN1(d.s); err != nil {
			return d.err("failed to decode with unmarshaler: %s", err)
		}
		return nil
	}
	d.c = CodingTypeOfKind(v)
	if d.c == UnknownType {
		return d.err("failed to get coding type of %s", v)
	}
	if d.c == MapType {
		if v.Type().Key() != reflect.TypeOf(asn1.Tag(0)) {
			return d.err("can only decode to map with keys of type asn1.Tag, not %s", v.Type().Key().Name())
		}
	}
	if d.tag == initTag {
		if err := d.fillTag(); err != nil {
			return err
		}
	}
	switch d.c {
	case IntType:
		switch v.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			var out int64
			if !d.s.ReadASN1Integer(&out) {
				return d.err("failed to decode int64")
			}
			v.SetInt(out)
		default:
			var out uint64
			if !d.s.ReadASN1Integer(&out) {
				return d.err("failed to decode uint64")
			}
			v.SetUint(out)
		}
	case StringType:
		return d.decodeString(v)
	case BoolType:
		var out bool
		if !d.s.ReadASN1Boolean(&out) {
			return d.err("failed to decode bool")
		}
		v.SetBool(out)
	case BytesType:
		return d.decodeBytes(v)
	case ArrayType:
		return d.decodeArray(v)
	case StructType, MapType:
		return d.decodeStruct(v)
	}
	return nil
}

func (d *decodeCtx) decodeString(v reflect.Value) error {
	// TODO: Support for other string formats!
	var out []byte
	if !d.s.ReadASN1Bytes(&out, d.tag) {
		return d.err("failed to decode string")
	}
	v.SetString(string(out))
	return nil
}

func (d *decodeCtx) decodeBytes(v reflect.Value) error {
	var out []byte
	if d.tag == asn1.BIT_STRING {
		if !d.s.ReadASN1BitStringAsBytes(&out) {
			return d.err("failed to decode bitstring as bytes")
		}
	} else if d.tag == asn1.OCTET_STRING {
		if !d.s.ReadASN1Bytes(&out, d.tag) {
			return d.err("failed to decode octet string as bytes")
		}
	} else {
		return d.err("tag %s not yet implemented for bytes", d.tag)
	}

	v.SetBytes(out)
	return nil
}

func (d *decodeCtx) decodeArray(v reflect.Value) error {
	var seq String
	if !d.s.ReadASN1(&seq, d.tag) {
		return d.err("failed to decode sequence / set")
	}
	i := 0
	for {
		// Look ahead for ] - can only happen on first iteration.
		var curr String
		if !seq.ReadAnyASN1Element(&curr, nil) {
			break
		}

		// Get element of array, growing if necessary.
		if v.Kind() == reflect.Slice {
			// Grow slice if necessary
			if i >= v.Cap() {
				newcap := v.Cap() + v.Cap()/2
				if newcap < 4 {
					newcap = 4
				}
				newv := reflect.MakeSlice(v.Type(), v.Len(), newcap)
				reflect.Copy(newv, v)
				v.Set(newv)
			}
			if i >= v.Len() {
				v.SetLen(i + 1)
			}
		}

		if i < v.Len() {
			// Decode into element.
			nctx := newDecodeCtx(v.Index(i), &curr, initTag)
			nctx.name = fmt.Sprintf("[%d]", i)
			nctx.parent = d
			if err := nctx.decode(); err != nil {
				return err
			}
		} else {
			// Ran out of fixed array: skip.
			return d.err("ran out of space in array")
		}
		i++
	}

	if i < v.Len() {
		if v.Kind() == reflect.Array {
			// Array. Zero the rest.
			z := reflect.Zero(v.Type().Elem())
			for ; i < v.Len(); i++ {
				v.Index(i).Set(z)
			}
		} else {
			v.SetLen(i)
		}
	}
	if i == 0 && v.Kind() == reflect.Slice {
		v.Set(reflect.MakeSlice(v.Type(), 0, 0))
	}
	return nil
}

func (d *decodeCtx) decodeStructField(field structField, elem *String) error {
	if field.params.nested {
		var nestedS String
		if !elem.ReadAnyASN1(&nestedS, nil) {
			return d.err("failed to decode nested element for struct field %s", field.Name)
		}
		elem = &nestedS
		field.params.tag = initTag // reset, since we used the tag only for the nested struct!
	}
	nctx := newDecodeCtx(field.v, elem, field.params.tag)
	nctx.name = field.Name
	nctx.parent = d
	return nctx.decode()
}

func (d *decodeCtx) decodeStruct(v reflect.Value) error {
	var seq String
	if !d.s.ReadASN1(&seq, d.tag) {
		return d.err("failed to decode sequence / set")
	}
	fs := getStructFields(v)
	i := 0
	for {
		if i >= len(fs) {
			break
		}
		var curr String
		var currT asn1.Tag
		if !seq.ReadAnyASN1Element(&curr, &currT) {
			return nil // end of set or sequence
		}
		newS := &curr
		field := fs[i]
		if d.tag == asn1.SET {
			// For set we have different semantics!
			tagFound := false
			for _, f := range fs {
				if f.params.tag == currT {
					field = f
					var nestedConts String
					if !curr.ReadAnyASN1(&nestedConts, nil) {
						return d.err("failed to decode nested contents in sequence!")
					}
					field.params.tag = initTag // reset, since we used the tag only for the key!
					newS = &nestedConts
					tagFound = true
					break
				}
			}
			if !tagFound {
				continue
			}
		}
		if err := d.decodeStructField(field, newS); err != nil {
			return err
		}
		i++
	}

	return nil
}

func (d *decodeCtx) buildPath() string {
	steps := []string{}
	curr := d
	for curr != nil {
		if curr.name != "" {
			steps = append([]string{curr.name}, steps...)
		}
		curr = curr.parent
	}
	return strings.Join(steps, ".")
}

func (d *decodeCtx) err(msg string, args ...interface{}) error {
	return fmt.Errorf("asn1: error decoding on path %s: %s", d.buildPath(), fmt.Sprintf(msg, args...))
}

func (d *decodeCtx) decode() error {
	return d.actDecode()
}

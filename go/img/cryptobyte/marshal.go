package cryptobyte

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/galli-leo/emmutaler/img/cryptobyte/asn1"
)

// Marshaler is the interface implemented by types that
// can marshal themselves into valid ASN.1.
type Marshaler interface {
	MarshalASN1(b *Builder, tag asn1.Tag) error
}

func Marshal(v interface{}) ([]byte, error) {
	val := reflect.ValueOf(v)
	ctx := newEncodeCtx(val, NewBuilder([]byte{}), initTag)
	err := ctx.encode()
	if err != nil {
		return []byte{}, err
	}
	return ctx.b.Bytes()
}

func MarshalStart(v interface{}, topTag asn1.Tag) ([]byte, error) {
	val := reflect.ValueOf(v)
	ctx := newEncodeCtx(val, NewBuilder([]byte{}), topTag)
	err := ctx.encode()
	if err != nil {
		return []byte{}, err
	}
	return ctx.b.Bytes()
}

func newEncodeCtx(v reflect.Value, b *Builder, tag asn1.Tag) *encodeCtx {
	e := &encodeCtx{
		v:   v,
		b:   b,
		tag: tag,
	}

	return e
}

type encodeCtx struct {
	parent *encodeCtx
	name   string
	v      reflect.Value
	b      *Builder
	c      CodingType
	tag    asn1.Tag
}

func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}
	return false
}

var (
	marshalerType = reflect.TypeOf((*Marshaler)(nil)).Elem()
)

func (e *encodeCtx) encode() error {
	e.c = CodingTypeOfKind(e.v)
	if e.tag == initTag {
		e.tag = e.c.EncodedTag()
	}

	if e.v.Kind() != reflect.Ptr && reflect.PtrTo(e.v.Type()).Implements(marshalerType) {
		if e.v.CanAddr() {
			va := e.v.Addr()
			return e.encodeMarshalPtr(va)
		}
	}

	if e.v.Type().Implements(marshalerType) {
		return e.encodeMarshalPtr(e.v)
	}

	// quickly encode nil, if that is it.
	if e.v.Kind() == reflect.Ptr && e.v.IsNil() {
		return e.encodeNil()
	}

	// not nil pointer, let's derefence that
	if e.v.Kind() == reflect.Ptr {
		e.v = e.v.Elem()
	}

	var err error = nil
	// TODO: What about ptrs???
	e.b.AddASN1(e.tag, func(b *Builder) {
		// temporarily change builder??
		actB := e.b
		e.b = b
		defer func() {
			e.b = actB
		}()

		// if we are bytes, just get the bytes!
		if e.c == BytesType {
			e.b.AddBytes(e.v.Bytes())
			return
		}

		switch e.v.Kind() {
		case reflect.Bool:
			e.b.addASN1Boolean(e.v.Bool())
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			e.b.addASN1Int(e.v.Int())
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			e.b.addASN1Uint(e.v.Uint())
		case reflect.String:
			e.b.AddBytes([]byte(e.v.String()))
		case reflect.Array, reflect.Slice:
			err = e.encodeArray()
		case reflect.Struct:
			err = e.encodeStruct()
		default:
			err = fmt.Errorf("cannot currently encode type %s", e.v.Kind())
		}
	})

	if err != nil {
		return e.err("failed to encode values: %s", err)
	}

	return nil
}

func (d *encodeCtx) encodeNil() error {
	d.b.AddASN1(asn1.NULL, func(child *Builder) {}) // actually how you encode null :)
	return nil
}

func (e *encodeCtx) encodeMarshalPtr(va reflect.Value) error {
	// va might also be interface I guess, not only ptr!
	if va.Kind() == reflect.Ptr && va.IsNil() {
		return e.encodeNil()
	}
	// Should always be fine?
	m := va.Interface().(Marshaler)
	// we pass along the tag, which the marshaler may freely ignore.
	err := m.MarshalASN1(e.b, e.tag)
	if err != nil {
		return e.err("failed to custom marshal: %s", err)
	}

	return nil
}

func (e *encodeCtx) encodeArray() error {
	for i := 0; i < e.v.Len(); i++ {
		nctx := newEncodeCtx(e.v.Index(i), e.b, initTag)
		nctx.name = fmt.Sprintf("[%d]", i)
		nctx.parent = e
		if err := nctx.encode(); err != nil {
			return err
		}
	}
	return nil
}

func (e *encodeCtx) encodeStructField(field structField, b *Builder) error {
	nctx := newEncodeCtx(field.v, b, field.params.tag)
	nctx.name = field.Name
	nctx.parent = e
	return nctx.encode()
}

func (e *encodeCtx) encodeStruct() error {
	fs := getStructFields(e.v)
	for _, f := range fs {
		fv := f.v
		if f.params.omitEmpty && isEmptyValue(fv) {
			continue
		}
		if f.params.skip {
			continue
		}
		// if we have a set, we are still nested!
		if f.params.nested || e.tag == asn1.SET {
			nestedTag := asn1.OCTET_STRING
			if f.params.tag != initTag {
				nestedTag = f.params.tag
			}
			if f.params.nested {
				f.params.tag = initTag // reset, since we used it for nesting!
				// we don't wanna reset for sets, since we might need the tag afterwards there!
				// TODO: This should be more general, if a set contains stuff with non ObjectIDs, this wont work!
			}
			var err error = nil
			e.b.AddASN1(nestedTag, func(child *Builder) {
				err = e.encodeStructField(f, child)
			})
			if err != nil {
				return err
			}
		} else {
			if err := e.encodeStructField(f, e.b); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *encodeCtx) buildPath() string {
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

func (d *encodeCtx) err(msg string, args ...interface{}) error {
	return fmt.Errorf("asn1: error decoding on path %s: %s", d.buildPath(), fmt.Sprintf(msg, args...))
}

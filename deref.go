/*
 * Copyright (c) 2020 Moriyoshi Koizumi
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *    * Neither the name of Elazar Leibovich. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package main

import (
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

type pathElementType int

const (
	pathElementTypeMap   = pathElementType(1)
	pathElementTypeArray = pathElementType(2)
)

type pathElement struct {
	t     pathElementType
	index int
	key   string
}

type path []pathElement

func (p path) String() string {
	var buf []byte
	for _, e := range p {
		switch e.t {
		case pathElementTypeMap:
			if len(buf) > 0 {
				buf = append(buf, '/')
			}
			if strings.IndexByte(e.key, '/') >= 0 {
				buf = strconv.AppendQuoteToGraphic(buf, e.key)
			} else {
				buf = append(buf, []byte(e.key)...)
			}
		case pathElementTypeArray:
			buf = append(buf, '[')
			buf = strconv.AppendInt(buf, int64(e.index), 10)
			buf = append(buf, ']')
		}
	}
	return string(buf)
}

func (p path) append(items ...interface{}) path {
	for _, item := range items {
		switch item := item.(type) {
		case string:
			p = append(p, pathElement{t: pathElementTypeMap, key: item})
		case int:
			p = append(p, pathElement{t: pathElementTypeArray, index: item})
		default:
			panic(fmt.Sprintf("unexpected element type: %T", item))
		}
	}
	return p
}

func parsePath(pathStr string) (p path, err error) {
	s := 0
	state := 0
	var keyBuf []rune
	for i, c := range pathStr {
		switch state {
		case 0:
			switch c {
			case '"':
				state = 2
			case '/':
				var key string
				if keyBuf == nil {
					key = pathStr[s:i]
				} else {
					key = string(keyBuf)
					keyBuf = keyBuf[0:0]
				}
				p = append(p, pathElement{t: pathElementTypeMap, key: key})
				s = i + 1
			case '[':
				var key string
				if keyBuf == nil {
					key = pathStr[s:i]
				} else {
					key = string(keyBuf)
					keyBuf = keyBuf[0:0]
				}
				p = append(p, pathElement{t: pathElementTypeMap, key: key})
				s = i + 1
				state = 1
			}
		case 1:
			switch c {
			case ']':
				var idx int
				idx, err = strconv.Atoi(pathStr[s:i])
				if err != nil {
					err = errors.Wrapf(err, "invalid array subscription after %s", p.String())
					return
				}
				p = append(p, pathElement{t: pathElementTypeArray, index: idx})
				state = 4
			}
		case 2:
			switch c {
			default:
				keyBuf = append(keyBuf, c)
			case '\\':
				state = 3
				break
			case '"':
				state = 0
				break
			}
		case 3:
			keyBuf = append(keyBuf, c)
			break
		case 4:
			switch c {
			default:
				err = errors.Errorf("invalid character '%c' after '['", c)
				return
			case '[':
				s = i + 1
				state = 1
			}
		}
	}
	return
}

type dereference struct {
	path         path
	value        interface{}
	pendingError error
}

type missingItemError struct {
	key string
}

func (e *missingItemError) Error() string {
	return fmt.Sprintf(`missing item "%s"`, e.key)
}

type indexOutOfRangeError struct {
	index int
}

func (e *indexOutOfRangeError) Error() string {
	return fmt.Sprintf(`index #%d out of range`, e.index)
}

type required struct {
	value interface{}
}

var yamlMapType = reflect.TypeOf(map[interface{}]interface{}{})
var emptyInterfaceType = reflect.TypeOf([0]interface{}{}).Elem()
var stringType = reflect.TypeOf("")
var boolType = reflect.TypeOf(false)
var intType = reflect.TypeOf(int(0))
var int16Type = reflect.TypeOf(int16(0))
var int32Type = reflect.TypeOf(int32(0))
var int64Type = reflect.TypeOf(int64(0))
var uintType = reflect.TypeOf(uint(0))
var uint16Type = reflect.TypeOf(uint16(0))
var uint32Type = reflect.TypeOf(uint32(0))
var uint64Type = reflect.TypeOf(uint64(0))
var float32Type = reflect.TypeOf(float32(0))
var float64Type = reflect.TypeOf(float64(0))
var errorType = reflect.TypeOf([0]error{}).Elem()
var dereferenceType = reflect.TypeOf(dereference{})

type derefError struct {
	inner error
	path  path
}

func (e *derefError) Error() string {
	return fmt.Sprintf("invalid structure under %s: %s", e.path.String(), e.inner.Error())
}

func (e *derefError) As(recv interface{}) bool {
	return errors.As(e, recv) || errors.As(e.inner, recv)
}

func isMissingItemError(e error) bool {
	var v *missingItemError
	return errors.As(e, &v)
}

func (deref dereference) wrap(err error) error {
	if _, ok := err.(*derefError); ok {
		return err
	} else {
		return &derefError{err, deref.path}
	}
}

func (deref dereference) errorf(fmt string, args ...interface{}) error {
	return deref.wrap(errors.Errorf(fmt, args...))
}

func (deref dereference) deref(subpath path) (newDeref dereference) {
	newDeref = deref
	if newDeref.pendingError != nil {
		return
	}
	for _, pe := range subpath {
		switch pe.t {
		case pathElementTypeMap:
			var mapValue map[interface{}]interface{}
			mapValue, err := deref.mapValue()
			if err != nil {
				newDeref.pendingError = err
				return
			}
			value, ok := mapValue[pe.key]
			if !ok {
				newDeref.pendingError = &missingItemError{pe.key}
				return
			}
			deref = dereference{append(deref.path, pe), value, nil}
		case pathElementTypeArray:
			sliceValue, err := deref.sliceValue()
			if err != nil {
				newDeref.pendingError = err
				return
			}
			if pe.index < 0 || pe.index >= len(sliceValue) {
				newDeref.pendingError = &indexOutOfRangeError{pe.index}
				return
			}
			value := sliceValue[pe.index]
			deref = dereference{append(deref.path, pe), value, nil}
		}
	}
	newDeref = deref
	return
}

func (deref dereference) derefOne(keyOrIndex interface{}) (newDeref dereference) {
	newDeref = deref
	if newDeref.pendingError != nil {
		return
	}
	switch keyOrIndex := keyOrIndex.(type) {
	case string:
		return deref.deref(path{{t: pathElementTypeMap, key: keyOrIndex}})
	case int:
		return deref.deref(path{{t: pathElementTypeMap, index: keyOrIndex}})
	default:
		newDeref.pendingError = deref.errorf("unexpected type %T", keyOrIndex)
	}
	return
}

func nilOrError(v interface{}) error {
	if v == nil {
		return nil
	}
	return v.(error)
}

func (deref dereference) multi(spec ...interface{}) error {
	if len(spec)%2 != 0 {
		return deref.errorf("the number of arguments must be multiple of 2")
	}

	for i := 0; i < len(spec); i += 2 {
		keyOrIndex := spec[i]
		v, required := keyOrIndex.(required)
		if required {
			keyOrIndex = v.value
		}
		deref := deref.derefOne(keyOrIndex)
		if deref.pendingError != nil {
			if !required {
				if isMissingItemError(deref.pendingError) {
					continue
				}
			}
			return deref.pendingError
		}
		switch cb := spec[i+1].(type) {
		case func(dereference) error:
			err := cb(deref)
			if err != nil {
				return deref.wrap(err)
			}
		case func(bool) error:
			v, err := deref.boolValue()
			if err != nil {
				return err
			}
			err = cb(v)
			if err != nil {
				return deref.wrap(err)
			}
		case func(int16) error:
			v, err := deref.intValue()
			if err != nil {
				return err
			}
			if v > math.MaxInt16 {
				return deref.errorf("value out of range; expecting an int16 value, got %d", v)
			}
			err = cb(int16(v))
			if err != nil {
				return deref.wrap(err)
			}
		case func(int32) error:
			v, err := deref.intValue()
			if err != nil {
				return err
			}
			if v > math.MaxInt32 {
				return deref.errorf("value out of range; expecting an int32 value, got %d", v)
			}
			err = cb(int32(v))
			if err != nil {
				return deref.wrap(err)
			}
		case func(int64) error:
			v, err := deref.intValue()
			if err != nil {
				return err
			}
			err = cb(int64(v))
			if err != nil {
				return deref.wrap(err)
			}
		case func(int) error:
			v, err := deref.intValue()
			if err != nil {
				return err
			}
			err = cb(int(v))
			if err != nil {
				return deref.wrap(err)
			}
		case func(uint16) error:
			v, err := deref.uintValue()
			if err != nil {
				return err
			}
			if v < 0 || v > math.MaxUint16 {
				return deref.errorf("value out of range; expecting an uint16 value, got %d", v)
			}
			err = cb(uint16(v))
			if err != nil {
				return deref.wrap(err)
			}
		case func(uint32) error:
			v, err := deref.uintValue()
			if err != nil {
				return err
			}
			if v < 0 || v > math.MaxUint32 {
				return deref.errorf("value out of range; expecting an uint32 value, got %d", v)
			}
			err = cb(uint32(v))
			if err != nil {
				return deref.wrap(err)
			}
		case func(uint64) error:
			v, err := deref.uintValue()
			if err != nil {
				return err
			}
			if v < 0 {
				return deref.errorf("value out of range; expecting an int64 value losslessly-convertible to uint64, got %d", v)
			}
			err = cb(uint64(v))
			if err != nil {
				return deref.wrap(err)
			}
		case func(uint) error:
			v, err := deref.uintValue()
			if err != nil {
				return err
			}
			if v < 0 {
				return deref.errorf("value out of range; expecting an int64 value losslessly-convertible to uint64, got %d", v)
			}
			err = cb(uint(v))
			if err != nil {
				return deref.wrap(err)
			}
		case func(float32) error:
			v, err := deref.floatValue()
			if err != nil {
				return err
			}
			err = cb(float32(v))
			if err != nil {
				return deref.wrap(err)
			}
		case func(float64) error:
			v, err := deref.floatValue()
			if err != nil {
				return err
			}
			err = cb(v)
			if err != nil {
				return deref.wrap(err)
			}
		case func(string) error:
			v, err := deref.stringValue()
			if err != nil {
				return err
			}
			err = cb(v)
			if err != nil {
				return deref.wrap(err)
			}
		default:
			cbv := reflect.ValueOf(cb)
			cbt := cbv.Type()
			if cbt.Kind() != reflect.Func {
				return deref.errorf("func type expected, got %s", cbt.String())
			}
			if cbt.NumOut() != 1 || cbt.Out(0) != errorType {
				return deref.errorf("expecting func type to return a single error, got %s", cbt.String())
			}
			switch cbt.NumIn() {
			case 1:
				t := cbt.In(0)
				switch t.Kind() {
				case reflect.Map:
					mapValue, err := deref.homogeneousMapValue(t.Elem())
					if err != nil {
						return err
					}
					return nilOrError(cbv.Call([]reflect.Value{reflect.ValueOf(mapValue)})[0].Interface())
				case reflect.Slice:
					sliceValue, err := deref.homogeneousSliceValue(t.Elem())
					if err != nil {
						return err
					}
					return nilOrError(cbv.Call([]reflect.Value{reflect.ValueOf(sliceValue)})[0].Interface())
				default:
					return deref.errorf("expecting first argument to receive a map or slice value, got %s", cbt.String())
				}
			case 2:
				inType := cbt.In(1)
				switch cbt.In(0) {
				case stringType:
					if inType == dereferenceType {
						return deref.iterateHomogeneousValuedMap(emptyInterfaceType, func(k string, deref dereference) error {
							return nilOrError(cbv.Call([]reflect.Value{reflect.ValueOf(k), reflect.ValueOf(deref)})[0].Interface())
						})
					} else {
						return deref.iterateHomogeneousValuedMap(inType, func(k string, deref dereference) error {
							return nilOrError(cbv.Call([]reflect.Value{reflect.ValueOf(k), reflect.ValueOf(deref.value)})[0].Interface())
						})
					}
				case intType:
					if inType == dereferenceType {
						return deref.iterateHomogeneousValuedSlice(emptyInterfaceType, func(i int, deref dereference) error {
							return nilOrError(cbv.Call([]reflect.Value{reflect.ValueOf(i), reflect.ValueOf(deref)})[0].Interface())
						})
					} else {
						return deref.iterateHomogeneousValuedSlice(inType, func(i int, deref dereference) error {
							return nilOrError(cbv.Call([]reflect.Value{reflect.ValueOf(i), reflect.ValueOf(deref.value)})[0].Interface())
						})
					}
				default:
					return deref.errorf("expecting first argument to receive an int or float value, got %s", cbt.String())
				}
			}
			return deref.errorf("func (dereference) error expected, got %T", cb)
		}
	}

	return nil
}

func (deref dereference) boolValue() (bool, error) {
	if deref.pendingError != nil {
		return false, deref.pendingError
	}
	boolVal, ok := deref.value.(bool)
	if !ok {
		return false, deref.errorf("boolean value expected, got %T", deref.value)
	}
	return boolVal, nil
}

func (deref dereference) intValue() (int, error) {
	if deref.pendingError != nil {
		return 0, deref.pendingError
	}
	switch value := deref.value.(type) {
	case int:
		return value, nil
	case float64:
		return int(value), nil
	default:
		return 0, deref.errorf("integer or float value expected, got %T", value)
	}
}

func (deref dereference) uintValue() (uint, error) {
	if deref.pendingError != nil {
		return 0, deref.pendingError
	}
	switch value := deref.value.(type) {
	case int:
		if value < 0 {
			return 0, deref.errorf("unsigned integer or float value expected, got %T", value)
		}
		return uint(value), nil
	case float64:
		if value < 0 {
			return 0, deref.errorf("unsigned integer or float value expected, got %T", value)
		}
		return uint(value), nil
	default:
		return 0, deref.errorf("integer or float value expected, got %T", deref.value)
	}
}

func (deref dereference) floatValue() (float64, error) {
	if deref.pendingError != nil {
		return 0, deref.pendingError
	}
	switch value := deref.value.(type) {
	case int:
		if value < 0 {
			return 0, deref.errorf("unsigned integer or float value expected, got %T", value)
		}
		return float64(value), nil
	case float64:
		if value < 0 {
			return 0, deref.errorf("unsigned integer or float value expected, got %T", value)
		}
		return value, nil
	default:
		return 0, deref.errorf("integer or float value expected, got %T", deref.value)
	}
}

func (deref dereference) stringValue() (string, error) {
	if deref.pendingError != nil {
		return "", deref.pendingError
	}
	strVal, ok := deref.value.(string)
	if !ok {
		return "", deref.errorf("string value expected, got %T", deref.value)
	}
	return strVal, nil
}

func (deref dereference) sliceValue() ([]interface{}, error) {
	if deref.pendingError != nil {
		return nil, deref.pendingError
	}
	sliceVal, ok := deref.value.([]interface{})
	if !ok {
		return nil, deref.errorf("array expected, got %T", deref.value)
	}
	return sliceVal, nil
}

func (deref dereference) valueAs(typ reflect.Type) (newDeref dereference) {
	newDeref.path = deref.path

	switch typ {
	case emptyInterfaceType:
		newDeref = deref
		return
	case boolType:
		newDeref.value, newDeref.pendingError = deref.boolValue()
		return
	case int16Type:
		v, err := deref.intValue()
		if err != nil {
			newDeref.pendingError = err
			return
		}
		if v > math.MaxInt16 {
			newDeref.pendingError = deref.errorf("value out of range; expecting an int16 value, got %d", v)
			return
		}
		newDeref.value = int16(v)
		return
	case int32Type:
		v, err := deref.intValue()
		if err != nil {
			newDeref.pendingError = err
			return
		}
		if v > math.MaxInt32 {
			newDeref.pendingError = deref.errorf("value out of range; expecting an int16 value, got %d", v)
			return
		}
		newDeref.value = int32(v)
		return
	case intType:
		newDeref.value, newDeref.pendingError = newDeref.intValue()
		return
	case int64Type:
		v, err := deref.intValue()
		if err != nil {
			newDeref.pendingError = err
			return
		}
		newDeref.value = int64(v)
		return
	case uint16Type:
		v, err := deref.uintValue()
		if err != nil {
			newDeref.pendingError = err
			return
		}
		if v < 0 || v > math.MaxUint16 {
			newDeref.pendingError = deref.errorf("value out of range; expecting an uint16 value, got %d", v)
			return
		}
		newDeref.value = uint16(v)
		return
	case uint32Type:
		v, err := deref.uintValue()
		if err != nil {
			newDeref.pendingError = err
			return
		}
		if v < 0 || v > math.MaxUint32 {
			newDeref.pendingError = deref.errorf("value out of range; expecting an uint32 value, got %d", v)
			return
		}
		newDeref.value = uint32(v)
		return
	case uint64Type:
		v, err := deref.uintValue()
		if err != nil {
			newDeref.pendingError = err
			return
		}
		if v < 0 {
			newDeref.pendingError = deref.errorf("value out of range; expecting an int64 value losslessly-convertible to uint64, got %d", v)
			return
		}
		newDeref.value = uint64(v)
		return
	case uintType:
		v, err := deref.uintValue()
		if err != nil {
			newDeref.pendingError = err
			return
		}
		if v < 0 {
			newDeref.pendingError = deref.errorf("value out of range; expecting an int64 value losslessly-convertible to uint64, got %d", v)
			return
		}
		newDeref.value = uint(v)
		return
	case float32Type:
		v, err := deref.floatValue()
		if err != nil {
			newDeref.pendingError = err
			return
		}
		newDeref.value = float32(v)
		return
	case float64Type:
		newDeref.value, newDeref.pendingError = deref.floatValue()
		return
	case stringType:
		newDeref.value, newDeref.pendingError = deref.stringValue()
		return
	default:
		switch typ.Kind() {
		case reflect.Map:
			newDeref.value, newDeref.pendingError = deref.homogeneousMapValue(typ.Elem())
			return
		case reflect.Slice:
			newDeref.value, newDeref.pendingError = deref.homogeneousSliceValue(typ.Elem())
			return
		default:
			newDeref.pendingError = deref.errorf("expecting a map or slice type, got %s", typ.String())
			return
		}
	}
}

func (deref dereference) homogeneousSliceValue(typ reflect.Type) (interface{}, error) {
	if deref.pendingError != nil {
		return nil, deref.pendingError
	}
	sliceVal, err := deref.sliceValue()
	if err != nil {
		return nil, err
	}
	hArrVal := reflect.MakeSlice(reflect.SliceOf(typ), len(sliceVal), len(sliceVal))
	for i, v := range sliceVal {
		dv := dereference{deref.path.append(i), v, nil}.valueAs(typ)
		if dv.pendingError != nil {
			return nil, dv.pendingError
		}
		hArrVal.Index(i).Set(reflect.ValueOf(dv.value))
	}
	return hArrVal.Interface(), nil
}

func (deref dereference) iterateHomogeneousValuedSlice(typ reflect.Type, cb func(i int, deref dereference) error) error {
	if deref.pendingError != nil {
		return deref.pendingError
	}
	sliceVal, err := deref.sliceValue()
	if err != nil {
		return err
	}
	for i, v := range sliceVal {
		dv := dereference{deref.path.append(i), v, nil}.valueAs(typ)
		if dv.pendingError != nil {
			return dv.pendingError
		}
		err = cb(i, dv)
		if err != nil {
			return dv.wrap(err)
		}
	}
	return nil
}

func (deref dereference) mapValue() (map[interface{}]interface{}, error) {
	if deref.pendingError != nil {
		return nil, deref.pendingError
	}
	mapVal, ok := deref.value.(map[interface{}]interface{})
	if !ok {
		return nil, deref.errorf("mapping expected, got %T", deref.value)
	}
	return mapVal, nil
}

func (deref dereference) homogeneousMapValue(typ reflect.Type) (interface{}, error) {
	if deref.pendingError != nil {
		return nil, deref.pendingError
	}
	mapVal, ok := deref.value.(map[interface{}]interface{})
	if !ok {
		return nil, deref.errorf("mapping of %s expected, got %T", deref.value)
	}
	hMapVal := reflect.MakeMap(reflect.MapOf(emptyInterfaceType, typ))
	for k, v := range mapVal {
		sk, ok := k.(string)
		if !ok {
			return nil, deref.errorf("expecting a string for a map key, got %T", deref.value)
		}
		dv := dereference{deref.path.append(k), v, nil}.valueAs(typ)
		if dv.pendingError != nil {
			return nil, dv.pendingError
		}
		hMapVal.SetMapIndex(reflect.ValueOf(sk), reflect.ValueOf(dv.value))
	}
	return hMapVal.Interface(), nil
}

func (deref dereference) iterateHomogeneousValuedMap(typ reflect.Type, cb func(key string, deref dereference) error) error {
	if deref.pendingError != nil {
		return deref.pendingError
	}
	mapVal, ok := deref.value.(map[interface{}]interface{})
	if !ok {
		return deref.errorf("mapping of %s expected, got %T", typ.String(), deref.value)
	}
	for k, v := range mapVal {
		sk, ok := k.(string)
		if !ok {
			return deref.errorf("expecting a string for a map key, got %T", deref.value)
		}
		dv := dereference{deref.path.append(k), v, nil}.valueAs(typ)
		if dv.pendingError != nil {
			return dv.pendingError
		}
		err := cb(sk, dv)
		if err != nil {
			return dv.wrap(err)
		}
	}
	return nil
}

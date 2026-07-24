// Copyright 2026 Eirik Haatveit, University of Oslo
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ecsencoder

import (
	"time"

	"go.uber.org/zap/zapcore"
)

// nestEncoder is a minimal, cursor-based zapcore.ObjectEncoder that accumulates
// fields into a nested map[string]interface{}.
//
// It exists specifically so that the ECS encoder composes correctly when it is
// the target of Caddy's "filter" encoder (`format filter { wrap ecs }`).
//
// The difference from zapcore.MapObjectEncoder is subtle but decisive.
// MapObjectEncoder.AddObject spawns a *child* encoder and hands it to the
// object marshaler, relying on the marshaler to write into that child. Caddy's
// FilterEncoder, however, replays every field back through a single wrapped
// encoder instance and reroutes nested object marshaling through its own
// wrapper (logObjectMarshalerWrapper) — which ignores the child encoder and
// feeds sub-fields straight back to the one wrapped instance. Streaming
// encoders (json/console) cope because they keep namespace state on that single
// instance; a child-spawning encoder does not, so every nested request.* field
// collapses onto the root object.
//
// nestEncoder keeps its own cursor stack on a single instance: AddObject /
// OpenNamespace descend by pushing a fresh map, and every leaf write targets
// the current top of stack. That mirrors how the streaming encoders behave, so
// nesting survives both direct use and filter-wrapping.
type nestEncoder struct {
	root  map[string]interface{}
	stack []map[string]interface{}
}

func newNestEncoder() *nestEncoder {
	root := map[string]interface{}{}
	return &nestEncoder{root: root, stack: []map[string]interface{}{root}}
}

// cur returns the map that leaf writes currently target.
func (n *nestEncoder) cur() map[string]interface{} {
	return n.stack[len(n.stack)-1]
}

// clone returns a nestEncoder with a shallow copy of the root map. Nested maps
// are shared and treated as immutable once built: toECS never mutates its
// input, and any subsequent With()/call-site fields only add top-level keys.
func (n *nestEncoder) clone() *nestEncoder {
	root := make(map[string]interface{}, len(n.root))
	for k, v := range n.root {
		root[k] = v
	}
	return &nestEncoder{root: root, stack: []map[string]interface{}{root}}
}

// --- nesting-aware methods -------------------------------------------------

// AddObject descends into a new nested object for the duration of the
// marshaler's execution, so sub-fields land inside it regardless of whether the
// marshaler writes to the encoder we pass or (as Caddy's filter does) reroutes
// them back to this same instance.
func (n *nestEncoder) AddObject(key string, marshaler zapcore.ObjectMarshaler) error {
	child := map[string]interface{}{}
	n.cur()[key] = child
	n.stack = append(n.stack, child)
	err := marshaler.MarshalLogObject(n)
	n.stack = n.stack[:len(n.stack)-1]
	return err
}

// OpenNamespace opens (and descends into) a nested namespace. Matching zapcore
// semantics, it does not auto-close; subsequent fields belong to the namespace.
func (n *nestEncoder) OpenNamespace(key string) {
	ns := map[string]interface{}{}
	n.cur()[key] = ns
	n.stack = append(n.stack, ns)
}

// AddArray flattens an array into a []interface{}. It borrows a throwaway
// MapObjectEncoder purely for its array-building machinery.
func (n *nestEncoder) AddArray(key string, marshaler zapcore.ArrayMarshaler) error {
	tmp := zapcore.NewMapObjectEncoder()
	if err := tmp.AddArray(key, marshaler); err != nil {
		return err
	}
	n.cur()[key] = tmp.Fields[key]
	return nil
}

// AddReflected stores an arbitrary value verbatim (json.Marshal handles it
// later).
func (n *nestEncoder) AddReflected(key string, value interface{}) error {
	n.cur()[key] = value
	return nil
}

// --- leaf methods ----------------------------------------------------------

func (n *nestEncoder) AddBinary(key string, value []byte)          { n.cur()[key] = value }
func (n *nestEncoder) AddByteString(key string, value []byte)      { n.cur()[key] = string(value) }
func (n *nestEncoder) AddBool(key string, value bool)              { n.cur()[key] = value }
func (n *nestEncoder) AddComplex128(key string, value complex128)  { n.cur()[key] = value }
func (n *nestEncoder) AddComplex64(key string, value complex64)    { n.cur()[key] = value }
func (n *nestEncoder) AddDuration(key string, value time.Duration) { n.cur()[key] = value }
func (n *nestEncoder) AddFloat64(key string, value float64)        { n.cur()[key] = value }
func (n *nestEncoder) AddFloat32(key string, value float32)        { n.cur()[key] = value }
func (n *nestEncoder) AddInt(key string, value int)                { n.cur()[key] = value }
func (n *nestEncoder) AddInt64(key string, value int64)            { n.cur()[key] = value }
func (n *nestEncoder) AddInt32(key string, value int32)            { n.cur()[key] = value }
func (n *nestEncoder) AddInt16(key string, value int16)            { n.cur()[key] = value }
func (n *nestEncoder) AddInt8(key string, value int8)              { n.cur()[key] = value }
func (n *nestEncoder) AddString(key, value string)                 { n.cur()[key] = value }
func (n *nestEncoder) AddTime(key string, value time.Time)         { n.cur()[key] = value }
func (n *nestEncoder) AddUint(key string, value uint)              { n.cur()[key] = value }
func (n *nestEncoder) AddUint64(key string, value uint64)          { n.cur()[key] = value }
func (n *nestEncoder) AddUint32(key string, value uint32)          { n.cur()[key] = value }
func (n *nestEncoder) AddUint16(key string, value uint16)          { n.cur()[key] = value }
func (n *nestEncoder) AddUint8(key string, value uint8)            { n.cur()[key] = value }
func (n *nestEncoder) AddUintptr(key string, value uintptr)        { n.cur()[key] = value }

// Interface guard.
var _ zapcore.ObjectEncoder = (*nestEncoder)(nil)

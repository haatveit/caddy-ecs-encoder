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

// Package ecsencoder provides a Caddy log encoder that emits access and runtime
// logs in Elastic Common Schema (ECS) format with proper nested objects.
package ecsencoder

import (
	"encoding/json"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

const (
	defaultECSVersion   = "8.11.0"
	defaultEventDataset = "caddy.access"
	defaultEventModule  = "caddy"
)

var bufferpool = buffer.NewPool()

func init() {
	caddy.RegisterModule(ECSEncoder{})
}

// ECSEncoder is a Caddy log encoder (caddy.logging.encoders.ecs) that remaps
// Caddy's structured log fields into a nested Elastic Common Schema document.
//
// It embeds a *nestEncoder so that context fields added via zap's
// logger.With() — which is how Caddy attaches the access log's "request"
// object — are captured into a map we own, with nesting preserved. EncodeEntry
// merges that accumulated context with the call-site fields, remaps the result
// via toECS, and marshals it as one JSON line.
//
// The cursor-based nestEncoder (rather than zapcore.MapObjectEncoder) is what
// lets the module be wrapped by Caddy's "filter" encoder
// (`format filter { wrap ecs }`) without collapsing nested request fields; see
// nest_encoder.go for the details.
type ECSEncoder struct {
	*nestEncoder `json:"-"`

	// ECSVersion is written to ecs.version on every event. Default "8.11.0".
	ECSVersion string `json:"ecs_version,omitempty"`
	// EventDataset is written to event.dataset. Default "caddy.access".
	EventDataset string `json:"event_dataset,omitempty"`
	// EventModule is written to event.module. Default "caddy".
	EventModule string `json:"event_module,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (ECSEncoder) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.ecs",
		New: func() caddy.Module { return new(ECSEncoder) },
	}
}

// Provision sets defaults and constructs the embedded encoder.
func (e *ECSEncoder) Provision(_ caddy.Context) error {
	if e.ECSVersion == "" {
		e.ECSVersion = defaultECSVersion
	}
	if e.EventDataset == "" {
		e.EventDataset = defaultEventDataset
	}
	if e.EventModule == "" {
		e.EventModule = defaultEventModule
	}
	// Backs the ObjectEncoder method set and accumulates any With() context.
	e.nestEncoder = newNestEncoder()
	return nil
}

func (e ECSEncoder) ecsConfig() ecsConfig {
	return ecsConfig{
		ECSVersion:   e.ECSVersion,
		EventDataset: e.EventDataset,
		EventModule:  e.EventModule,
	}
}

// Clone returns a copy of the encoder with its own copy of the accumulated
// context fields, as required by zapcore.Encoder. zap calls this on every
// logger.With(), then replays the new context fields into the clone.
func (e ECSEncoder) Clone() zapcore.Encoder {
	clone := e
	if e.nestEncoder != nil {
		clone.nestEncoder = e.nestEncoder.clone()
	} else {
		clone.nestEncoder = newNestEncoder()
	}
	return clone
}

// EncodeEntry merges the accumulated With() context with the call-site fields,
// remaps the result to ECS, and serializes it as a single JSON line.
func (e ECSEncoder) EncodeEntry(ent zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	merged := newNestEncoder()
	if e.nestEncoder != nil {
		for k, v := range e.nestEncoder.root {
			merged.root[k] = v
		}
	}
	for i := range fields {
		fields[i].AddTo(merged)
	}

	doc := toECS(ent, merged.root, e.ecsConfig())

	data, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}

	buf := bufferpool.Get()
	_, _ = buf.Write(data)
	buf.AppendByte('\n')
	return buf, nil
}

// UnmarshalCaddyfile configures the encoder from Caddyfile tokens:
//
//	format ecs {
//	    ecs_version   8.11.0
//	    event_dataset caddy.access
//	    event_module  caddy
//	}
func (e *ECSEncoder) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume "ecs"
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "ecs_version":
			if !d.NextArg() {
				return d.ArgErr()
			}
			e.ECSVersion = d.Val()
		case "event_dataset":
			if !d.NextArg() {
				return d.ArgErr()
			}
			e.EventDataset = d.Val()
		case "event_module":
			if !d.NextArg() {
				return d.ArgErr()
			}
			e.EventModule = d.Val()
		default:
			return d.Errf("unrecognized subdirective %q", d.Val())
		}
	}
	return nil
}

// Interface guards.
var (
	_ caddy.Module          = (*ECSEncoder)(nil)
	_ caddy.Provisioner     = (*ECSEncoder)(nil)
	_ zapcore.Encoder       = (*ECSEncoder)(nil)
	_ caddyfile.Unmarshaler = (*ECSEncoder)(nil)
)

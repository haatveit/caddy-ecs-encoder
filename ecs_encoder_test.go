package ecsencoder

import (
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestCaddyModuleID(t *testing.T) {
	id := ECSEncoder{}.CaddyModule().ID
	if id != "caddy.logging.encoders.ecs" {
		t.Fatalf("module ID = %q, want caddy.logging.encoders.ecs", id)
	}
}

func TestProvisionDefaults(t *testing.T) {
	e := new(ECSEncoder)
	if err := e.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if e.ECSVersion != defaultECSVersion {
		t.Errorf("ECSVersion = %q, want %q", e.ECSVersion, defaultECSVersion)
	}
	if e.EventDataset != defaultEventDataset {
		t.Errorf("EventDataset = %q, want %q", e.EventDataset, defaultEventDataset)
	}
	if e.EventModule != defaultEventModule {
		t.Errorf("EventModule = %q, want %q", e.EventModule, defaultEventModule)
	}
	if e.MapObjectEncoder == nil {
		t.Error("embedded MapObjectEncoder must be non-nil after Provision")
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	d := caddyfile.NewTestDispenser(`ecs {
		ecs_version 9.0.0
		event_dataset my.dataset
		event_module mymod
	}`)
	var e ECSEncoder
	if err := e.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if e.ECSVersion != "9.0.0" {
		t.Errorf("ECSVersion = %q, want 9.0.0", e.ECSVersion)
	}
	if e.EventDataset != "my.dataset" {
		t.Errorf("EventDataset = %q, want my.dataset", e.EventDataset)
	}
	if e.EventModule != "mymod" {
		t.Errorf("EventModule = %q, want mymod", e.EventModule)
	}
}

func TestUnmarshalCaddyfileUnknownDirective(t *testing.T) {
	d := caddyfile.NewTestDispenser(`ecs {
		bogus value
	}`)
	var e ECSEncoder
	if err := e.UnmarshalCaddyfile(d); err == nil {
		t.Fatal("expected error for unknown subdirective, got nil")
	}
}

func TestUnmarshalCaddyfileNoBlock(t *testing.T) {
	d := caddyfile.NewTestDispenser(`ecs`)
	var e ECSEncoder
	if err := e.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile with no block: %v", err)
	}
}

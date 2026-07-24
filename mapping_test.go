package ecsencoder

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// --- test helpers that mirror how Caddy emits access-log fields -------------

type stringArray []string

func (s stringArray) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for _, v := range s {
		enc.AppendString(v)
	}
	return nil
}

// headerMarshaler mirrors Caddy's header logging: a map of name -> []string.
type headerMarshaler map[string][]string

func (h headerMarshaler) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	for k, vs := range h {
		if err := enc.AddArray(k, stringArray(vs)); err != nil {
			return err
		}
	}
	return nil
}

// tlsMarshaler mirrors Caddy's LoggableTLSConnState (numeric version/cipher).
type tlsMarshaler struct {
	version     uint16
	cipherSuite uint16
	proto       string
	serverName  string
	resumed     bool
}

func (t tlsMarshaler) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddBool("resumed", t.resumed)
	enc.AddUint16("version", t.version)
	enc.AddUint16("cipher_suite", t.cipherSuite)
	enc.AddString("proto", t.proto)
	enc.AddString("server_name", t.serverName)
	return nil
}

// requestMarshaler mirrors Caddy's LoggableHTTPRequest.
type requestMarshaler struct {
	remoteIP   string
	remotePort string
	clientIP   string
	proto      string
	method     string
	host       string
	uri        string
	headers    headerMarshaler
	tls        *tlsMarshaler
}

func (r requestMarshaler) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("remote_ip", r.remoteIP)
	enc.AddString("remote_port", r.remotePort)
	if r.clientIP != "" {
		enc.AddString("client_ip", r.clientIP)
	}
	enc.AddString("proto", r.proto)
	enc.AddString("method", r.method)
	enc.AddString("host", r.host)
	enc.AddString("uri", r.uri)
	if r.headers != nil {
		if err := enc.AddObject("headers", r.headers); err != nil {
			return err
		}
	}
	if r.tls != nil {
		if err := enc.AddObject("tls", r.tls); err != nil {
			return err
		}
	}
	return nil
}

// encode runs a set of fields through a provisioned ECSEncoder and returns the
// decoded JSON document.
func encode(t *testing.T, ent zapcore.Entry, fields []zapcore.Field) map[string]interface{} {
	t.Helper()
	enc := new(ECSEncoder)
	if err := enc.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	buf, err := enc.EncodeEntry(ent, fields)
	if err != nil {
		t.Fatalf("EncodeEntry: %v", err)
	}
	defer buf.Free()
	if n := len(buf.Bytes()); n == 0 || buf.Bytes()[n-1] != '\n' {
		t.Fatalf("output must end with a newline")
	}
	var out map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	return out
}

// get navigates a dotted path through nested maps, returning nil if absent.
func get(t *testing.T, m map[string]interface{}, path string) interface{} {
	t.Helper()
	cur := interface{}(m)
	for _, p := range splitPath(path) {
		if cur == nil {
			return nil // a parent along the path is absent
		}
		mp, ok := cur.(map[string]interface{})
		if !ok {
			t.Fatalf("path %q: segment before %q is not an object (%T)", path, p, cur)
		}
		cur = mp[p]
	}
	return cur
}

func splitPath(path string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(path); i++ {
		if path[i] == '.' {
			parts = append(parts, path[start:i])
			start = i + 1
		}
	}
	return append(parts, path[start:])
}

func assertEq(t *testing.T, m map[string]interface{}, path string, want interface{}) {
	t.Helper()
	got := get(t, m, path)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %#v, want %#v", path, got, want)
	}
}

func accessEntry() zapcore.Entry {
	return zapcore.Entry{
		Level:      zapcore.InfoLevel,
		Time:       time.Date(2022, 3, 9, 22, 30, 1, 524000000, time.UTC),
		LoggerName: "http.log.access",
		Message:    "handled request",
	}
}

// --- tests -----------------------------------------------------------------

func TestEncodeHTTPSRequest(t *testing.T) {
	fields := []zapcore.Field{
		zap.Object("request", requestMarshaler{
			remoteIP:   "192.0.2.10",
			remotePort: "54321",
			proto:      "HTTP/2.0",
			method:     "GET",
			host:       "example.com",
			uri:        "/search?q=cats",
			headers: headerMarshaler{
				"User-Agent": {"curl/7.82.0"},
				"Referer":    {"https://example.com/"},
			},
			tls: &tlsMarshaler{
				version:     772, // TLS 1.3
				cipherSuite: 4865,
				proto:       "h2",
				serverName:  "example.com",
				resumed:     false,
			},
		}),
		zap.Int("bytes_read", 0),
		zap.String("user_id", ""),
		zap.Duration("duration", 929675*time.Nanosecond),
		zap.Int("size", 10900),
		zap.Int("status", 200),
		zap.Object("resp_headers", headerMarshaler{
			"Content-Type": {"text/html; charset=utf-8"},
		}),
	}

	out := encode(t, accessEntry(), fields)

	// envelope + constants
	assertEq(t, out, "@timestamp", "2022-03-09T22:30:01.524Z")
	assertEq(t, out, "ecs.version", "8.11.0")
	assertEq(t, out, "log.level", "info")
	assertEq(t, out, "log.logger", "http.log.access")
	assertEq(t, out, "message", "handled request")
	assertEq(t, out, "event.kind", "event")
	assertEq(t, out, "event.dataset", "caddy.access")
	assertEq(t, out, "event.module", "caddy")
	assertEq(t, out, "network.protocol", "http")
	assertEq(t, out, "network.transport", "tcp")

	// event.category / type are arrays
	if cat, ok := get(t, out, "event.category").([]interface{}); !ok || len(cat) != 1 || cat[0] != "web" {
		t.Errorf("event.category = %#v, want [web]", get(t, out, "event.category"))
	}
	if typ, ok := get(t, out, "event.type").([]interface{}); !ok || len(typ) != 1 || typ[0] != "access" {
		t.Errorf("event.type = %#v, want [access]", get(t, out, "event.type"))
	}

	// http
	assertEq(t, out, "http.request.method", "GET")
	assertEq(t, out, "http.version", "2.0")
	assertEq(t, out, "http.request.body.bytes", float64(0))
	assertEq(t, out, "http.response.body.bytes", float64(10900))
	assertEq(t, out, "http.response.status_code", float64(200))
	assertEq(t, out, "http.request.referrer", "https://example.com/")

	// url
	assertEq(t, out, "url.scheme", "https")
	assertEq(t, out, "url.domain", "example.com")
	assertEq(t, out, "url.original", "/search?q=cats")
	assertEq(t, out, "url.path", "/search")
	assertEq(t, out, "url.query", "q=cats")
	assertEq(t, out, "url.full", "https://example.com/search?q=cats")

	// source / client / network
	assertEq(t, out, "source.ip", "192.0.2.10")
	assertEq(t, out, "source.address", "192.0.2.10")
	assertEq(t, out, "source.port", float64(54321))
	assertEq(t, out, "client.ip", "192.0.2.10") // mirrored from peer (no client_ip)
	assertEq(t, out, "network.type", "ipv4")

	// event
	assertEq(t, out, "event.outcome", "success")
	assertEq(t, out, "event.duration", float64(929675)) // nanoseconds

	// user_agent + headers preserved
	assertEq(t, out, "user_agent.original", "curl/7.82.0")
	assertEq(t, out, "http.request.headers.User-Agent", []interface{}{"curl/7.82.0"})
	assertEq(t, out, "http.response.headers.Content-Type", []interface{}{"text/html; charset=utf-8"})

	// tls
	assertEq(t, out, "tls.version", "1.3")
	assertEq(t, out, "tls.version_protocol", "tls")
	assertEq(t, out, "tls.cipher", "TLS_AES_128_GCM_SHA256")
	assertEq(t, out, "tls.next_protocol", "h2")
	assertEq(t, out, "tls.client.server_name", "example.com")
	assertEq(t, out, "tls.resumed", false)
	assertEq(t, out, "tls.established", true)

	// user_id was empty -> omitted
	if v := get(t, out, "user.name"); v != nil {
		t.Errorf("user.name should be omitted for empty user_id, got %#v", v)
	}
}

func TestEncodePlainHTTPWithClientIP(t *testing.T) {
	fields := []zapcore.Field{
		zap.Object("request", requestMarshaler{
			remoteIP:   "10.0.0.1", // proxy
			remotePort: "40000",
			clientIP:   "203.0.113.7", // real client via trusted_proxies
			proto:      "HTTP/1.1",
			method:     "POST",
			host:       "api.example.com:8080",
			uri:        "/v1/things",
		}),
		zap.Int("status", 404),
		zap.String("user_id", "alice"),
		zap.Duration("duration", 2*time.Millisecond),
	}

	out := encode(t, accessEntry(), fields)

	assertEq(t, out, "url.scheme", "http")
	assertEq(t, out, "url.domain", "api.example.com")
	assertEq(t, out, "url.port", float64(8080))
	assertEq(t, out, "server.port", float64(8080))
	assertEq(t, out, "url.full", "http://api.example.com:8080/v1/things")
	assertEq(t, out, "http.version", "1.1")
	assertEq(t, out, "source.ip", "10.0.0.1")
	assertEq(t, out, "client.ip", "203.0.113.7")
	assertEq(t, out, "client.address", "203.0.113.7")
	assertEq(t, out, "http.response.status_code", float64(404))
	assertEq(t, out, "event.outcome", "failure")
	assertEq(t, out, "event.duration", float64(2*time.Millisecond))
	assertEq(t, out, "user.name", "alice")

	// no TLS block emitted
	if v := get(t, out, "tls"); v != nil {
		t.Errorf("tls should be absent for plain HTTP, got %#v", v)
	}
}

func TestEncodeErroredRequest(t *testing.T) {
	ent := accessEntry()
	ent.Level = zapcore.ErrorLevel
	fields := []zapcore.Field{
		zap.Object("request", requestMarshaler{
			remoteIP: "192.0.2.1", remotePort: "1", proto: "HTTP/1.1",
			method: "GET", host: "x", uri: "/",
		}),
		zap.Int("status", 502),
		zap.String("error", "dial upstream: connection refused"),
	}

	out := encode(t, ent, fields)

	assertEq(t, out, "log.level", "error")
	assertEq(t, out, "event.outcome", "failure")
	assertEq(t, out, "error.message", "dial upstream: connection refused")
}

func TestCustomFieldGoesToLabels(t *testing.T) {
	fields := []zapcore.Field{
		zap.Object("request", requestMarshaler{
			remoteIP: "192.0.2.1", remotePort: "1", proto: "HTTP/1.1",
			method: "GET", host: "x", uri: "/",
		}),
		zap.Int("status", 200),
		zap.String("custom_field", "hello"),
	}

	out := encode(t, accessEntry(), fields)
	assertEq(t, out, "labels.custom_field", "hello")
}

func TestRuntimeLogNonAccess(t *testing.T) {
	ent := zapcore.Entry{
		Level:      zapcore.InfoLevel,
		Time:       time.Date(2022, 3, 9, 22, 30, 1, 0, time.UTC),
		LoggerName: "tls",
		Message:    "certificate obtained successfully",
	}
	fields := []zapcore.Field{
		zap.String("identifier", "example.com"), // scalar -> labels
		zap.Object("renewal", headerMarshaler{ // structured -> caddy.*
			"names": {"example.com"},
		}),
	}

	out := encode(t, ent, fields)

	assertEq(t, out, "log.logger", "tls")
	assertEq(t, out, "message", "certificate obtained successfully")
	assertEq(t, out, "event.kind", "event")
	assertEq(t, out, "labels.identifier", "example.com")
	assertEq(t, out, "caddy.renewal.names", []interface{}{"example.com"})

	// non-access: no web/access category or network fields
	if v := get(t, out, "event.category"); v != nil {
		t.Errorf("event.category should be absent for non-access logs, got %#v", v)
	}
	if v := get(t, out, "network.protocol"); v != nil {
		t.Errorf("network.protocol should be absent for non-access logs, got %#v", v)
	}
}

// TestContextFieldsFromWith reproduces how Caddy actually emits access logs:
// the "request" object is attached via logger.With() (baked into the encoder at
// clone time), while status/size/etc. arrive as call-site fields. Both must
// appear in the output.
func TestContextFieldsFromWith(t *testing.T) {
	base := new(ECSEncoder)
	if err := base.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	// logger.With(zap.Object("request", ...)) -> Clone then AddTo the clone.
	clone := base.Clone().(ECSEncoder)
	zap.Object("request", requestMarshaler{
		remoteIP: "192.0.2.10", remotePort: "54321", proto: "HTTP/1.1",
		method: "GET", host: "example.com", uri: "/",
		headers: headerMarshaler{"User-Agent": {"curl/8"}},
	}).AddTo(clone)

	// logger.Info("handled request", zap.Int("status", 200), ...)
	buf, err := clone.EncodeEntry(accessEntry(), []zapcore.Field{
		zap.Int("status", 200),
		zap.Int("size", 5),
	})
	if err != nil {
		t.Fatalf("EncodeEntry: %v", err)
	}
	defer buf.Free()

	var out map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// context field (request) survived the With()/EncodeEntry boundary
	assertEq(t, out, "http.request.method", "GET")
	assertEq(t, out, "url.domain", "example.com")
	assertEq(t, out, "source.ip", "192.0.2.10")
	assertEq(t, out, "user_agent.original", "curl/8")
	// call-site field
	assertEq(t, out, "http.response.status_code", float64(200))
	// treated as an access log
	if get(t, out, "event.category") == nil {
		t.Error("event.category should be present for access logs")
	}
}

// filterMimic reproduces the essential behavior of Caddy's FilterEncoder that
// used to break nesting: it replays fields into a single wrapped encoder
// instance, and for nested objects it reroutes the object marshaler back
// through *itself* (via filterObjWrap) rather than the child encoder that
// AddObject passes. This is exactly logObjectMarshalerWrapper in
// modules/logging/filterencoder.go. Embedding the ObjectEncoder interface gives
// us the leaf/array delegations for free; we only override AddObject.
type filterMimic struct {
	zapcore.ObjectEncoder
}

func (f filterMimic) AddObject(key string, m zapcore.ObjectMarshaler) error {
	return f.ObjectEncoder.AddObject(key, filterObjWrap{enc: f, marsh: m})
}

type filterObjWrap struct {
	enc   filterMimic
	marsh zapcore.ObjectMarshaler
}

func (o filterObjWrap) MarshalLogObject(_ zapcore.ObjectEncoder) error {
	return o.marsh.MarshalLogObject(o.enc)
}

// TestFilterWrapPreservesNesting guards against the regression where wrapping
// the ECS encoder with Caddy's filter encoder (`format filter { wrap ecs }`)
// flattened every request.* sub-field onto the root — scattering method/host/
// uri into labels.* and headers into caddy.*. With the cursor-based
// nestEncoder, nesting survives the filter's replay-through-one-instance model.
func TestFilterWrapPreservesNesting(t *testing.T) {
	base := new(ECSEncoder)
	if err := base.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	// Caddy's filter clones the wrapped encoder per entry and replays all fields
	// (including the With()-attached request) through it via the wrapper.
	clone := base.Clone().(ECSEncoder)
	mimic := filterMimic{ObjectEncoder: clone}

	zap.Object("request", requestMarshaler{
		remoteIP: "192.0.2.10", remotePort: "54321", proto: "HTTP/1.1",
		method: "GET", host: "example.com", uri: "/search?q=cats",
		headers: headerMarshaler{"User-Agent": {"curl/8"}},
	}).AddTo(mimic)
	zap.Int("status", 200).AddTo(mimic)
	zap.Int("size", 5).AddTo(mimic)

	// filter calls wrapped.EncodeEntry(ent, nil) — everything is already staged.
	buf, err := clone.EncodeEntry(accessEntry(), nil)
	if err != nil {
		t.Fatalf("EncodeEntry: %v", err)
	}
	defer buf.Free()

	var out map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Nested request fields must land in their ECS homes, not labels.*/caddy.*.
	assertEq(t, out, "http.request.method", "GET")
	assertEq(t, out, "url.domain", "example.com")
	assertEq(t, out, "url.path", "/search")
	assertEq(t, out, "source.ip", "192.0.2.10")
	assertEq(t, out, "source.port", float64(54321))
	assertEq(t, out, "user_agent.original", "curl/8")
	assertEq(t, out, "http.request.headers.User-Agent", []interface{}{"curl/8"})
	assertEq(t, out, "http.response.status_code", float64(200))
	assertEq(t, out, "http.response.body.bytes", float64(5))

	// None of the request fields should have leaked into labels.
	if v := get(t, out, "labels.method"); v != nil {
		t.Errorf("labels.method should not exist; filter-wrap flattened nesting: %#v", v)
	}
	if v := get(t, out, "labels.host"); v != nil {
		t.Errorf("labels.host should not exist; filter-wrap flattened nesting: %#v", v)
	}
}

func TestTLSVersionMapping(t *testing.T) {
	cases := map[uint16][2]string{
		0x0300: {"3.0", "ssl"},
		0x0301: {"1.0", "tls"},
		0x0302: {"1.1", "tls"},
		0x0303: {"1.2", "tls"},
		0x0304: {"1.3", "tls"},
		0x9999: {"", ""},
	}
	for in, want := range cases {
		gotV, gotP := tlsVersionString(in)
		if gotV != want[0] || gotP != want[1] {
			t.Errorf("tlsVersionString(%#x) = (%q,%q), want (%q,%q)", in, gotV, gotP, want[0], want[1])
		}
	}
}
